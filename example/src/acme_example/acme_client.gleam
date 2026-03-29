import acme_example/certificate
import acme_example/challenge_store
import acme_example/storage
import acme_example/utils
import acumen
import acumen/account
import acumen/challenge.{type Challenge}
import acumen/create_order
import acumen/fetch_authorization
import acumen/fetch_certificate
import acumen/fetch_order
import acumen/fetch_renewal_info
import acumen/finalize_order
import acumen/nonce
import acumen/order.{type Order}
import acumen/register_account
import acumen/url.{type Url}
import acumen/validate_challenge
import gleam/bool
import gleam/erlang/process
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/time/calendar
import gleam/time/duration.{type Duration}
import gleam/time/timestamp
import gleam/uri
import kryptos/ec

pub type Config {
  Config(
    domain: String,
    email: String,
    directory_url: String,
    http_port: Int,
    https_port: Int,
    storage_path: String,
    cert_path: String,
    key_path: String,
    profile: Option(String),
    challenge_type: challenge.ChallengeType,
    replaces: Option(String),
    eab: Option(account.ExternalAccountBinding),
  )
}

pub type AcmeClientError {
  HttpError(httpc.HttpError)
  AcmeError(acumen.AcmeError)
  ExecuteError(acumen.ExecuteError(httpc.HttpError))
  StorageError(storage.StorageError)
  CsrGenerationError
  NoChallengeFound(available: List(Challenge))
  UnsupportedChallengeType(String)
  OrderNotReady(String)
  InvalidDirectoryUrl
}

type PollResult {
  PollResult(
    order: Order,
    ctx: acumen.Context,
    next_retry_after: Option(Duration),
  )
}

@external(erlang, "acme_example_ffi", "get_line")
fn get_line(prompt: String) -> String

@external(erlang, "acme_example_ffi", "lookup_txt")
fn lookup_txt(domain: String) -> List(String)

pub fn run(
  config: Config,
  store: process.Subject(challenge_store.Message),
) -> Result(Nil, AcmeClientError) {
  io.println("\n=== ACME Certificate Issuance ===")
  io.println("Domain: " <> config.domain)
  io.println("Email: " <> config.email)
  io.println("Directory: " <> config.directory_url)
  case config.profile {
    option.Some(p) -> io.println("Profile: " <> p)
    option.None -> Nil
  }
  io.println("")

  use #(ctx, key) <- result.try(initialize(config))
  use #(ctx, acme_order) <- result.try(create_order(config, ctx, key))
  use ctx <- result.try(process_authorizations(
    config,
    store,
    ctx,
    key,
    acme_order.authorizations,
  ))
  use #(ctx, acme_order, cert_key) <- result.try(wait_for_ready(
    ctx,
    key,
    acme_order,
  ))
  use #(ctx, cert_url) <- result.try(finalize(ctx, key, acme_order, cert_key))
  use _ <- result.try(download_certificate(config, ctx, key, cert_url, cert_key))

  io.println("\n=== Certificate issuance complete! ===\n")
  Ok(Nil)
}

fn initialize(
  config: Config,
) -> Result(#(acumen.Context, acumen.RegisteredKey), AcmeClientError) {
  io.println("[Directory] Fetching ACME directory...")
  use directory <- result.try(fetch_directory(config.directory_url))
  io.println("  Directory fetched successfully")

  case acumen.external_account_required(directory), config.eab {
    True, option.None -> {
      io.println(
        "  Error: Server requires external account binding but none provided",
      )
      utils.halt(1)
    }
    _, _ -> Nil
  }

  io.println("[Nonce] Getting initial nonce...")
  use initial_nonce <- result.try(get_nonce(directory))
  io.println("  Nonce obtained")
  let ctx = acumen.Context(directory:, nonce: initial_nonce)

  case storage.load_account_key(config.storage_path) {
    Ok(registered_key) -> {
      io.println("[Account] Loaded existing account key")
      io.println("  Account URL: " <> url.to_string(registered_key.kid))
      Ok(#(ctx, registered_key))
    }
    Error(storage.KeyNotFound) -> {
      io.println("[Account] Generating new account key...")
      let account_key = storage.generate_account_key()
      io.println("  Account key generated (EC P-256)")
      register(config, ctx, account_key)
    }
    Error(err) -> Error(StorageError(err))
  }
}

fn register(
  config: Config,
  ctx: acumen.Context,
  account_key: acumen.UnregisteredKey,
) -> Result(#(acumen.Context, acumen.RegisteredKey), AcmeClientError) {
  io.println("[Account] Registering account...")
  let registration =
    register_account.request()
    |> register_account.contacts(["mailto:" <> config.email])
    |> register_account.agree_to_terms

  let registration = case config.eab {
    option.Some(eab) -> {
      io.println(
        "  Using external account binding (key ID: " <> eab.key_id <> ")",
      )
      register_account.external_account_binding(
        registration,
        key_id: eab.key_id,
        mac_key: eab.mac_key,
      )
    }
    option.None -> registration
  }

  use #(resp, ctx) <- result.try(
    acumen.execute(
      ctx,
      build: register_account.build(registration, _, account_key),
      send: httpc.send,
    )
    |> result.map_error(ExecuteError),
  )

  use #(_, registered_key) <- result.try(
    register_account.response(resp, account_key)
    |> result.map_error(AcmeError),
  )

  io.println("  Account registered")
  io.println("  Account URL: " <> url.to_string(registered_key.kid))

  use _ <- result.try(
    storage.save_account_key(config.storage_path, registered_key)
    |> result.map_error(StorageError),
  )

  Ok(#(ctx, registered_key))
}

fn create_order(
  config: Config,
  ctx: acumen.Context,
  registered_key: acumen.RegisteredKey,
) -> Result(#(acumen.Context, Order), AcmeClientError) {
  io.println("[Order] Creating order for " <> config.domain <> "...")
  let assert Ok(order_request) =
    create_order.request(identifiers: [acumen.DnsIdentifier(config.domain)])

  let order_request = case config.profile {
    option.Some(profile) -> create_order.profile(order_request, profile)
    option.None -> order_request
  }

  let order_request = case config.replaces {
    option.Some(cert_id) -> {
      io.println("  Replacing certificate: " <> cert_id)
      create_order.replaces(order_request, cert_id)
    }
    option.None -> order_request
  }

  use #(resp, ctx) <- result.try(
    acumen.execute(
      ctx,
      build: create_order.build(order_request, _, registered_key),
      send: httpc.send,
    )
    |> result.map_error(ExecuteError),
  )

  use acme_order <- result.try(
    create_order.response(resp)
    |> result.map_error(AcmeError),
  )

  io.println("  Order created")
  Ok(#(ctx, acme_order))
}

fn process_authorizations(
  config: Config,
  store: process.Subject(challenge_store.Message),
  ctx: acumen.Context,
  registered_key: acumen.RegisteredKey,
  remaining: List(Url),
) -> Result(acumen.Context, AcmeClientError) {
  case remaining {
    [] -> Ok(ctx)
    [auth_url, ..rest] -> {
      use #(ctx, challenge) <- result.try(fetch_and_deploy_challenge(
        config,
        store,
        ctx,
        registered_key,
        auth_url,
      ))
      use ctx <- result.try(trigger_validation(ctx, registered_key, challenge))
      process_authorizations(config, store, ctx, registered_key, rest)
    }
  }
}

fn fetch_and_deploy_challenge(
  config: Config,
  store: process.Subject(challenge_store.Message),
  ctx: acumen.Context,
  registered_key: acumen.RegisteredKey,
  auth_url: Url,
) -> Result(#(acumen.Context, Challenge), AcmeClientError) {
  io.println("[Authorization] Fetching authorization...")

  use #(resp, ctx) <- result.try(
    acumen.execute(
      ctx,
      build: fetch_authorization.build(auth_url, _, registered_key),
      send: httpc.send,
    )
    |> result.map_error(ExecuteError),
  )

  use auth <- result.try(
    fetch_authorization.response(resp, auth_url)
    |> result.map_error(AcmeError),
  )

  use challenge <- result.try(
    challenge.find_by_type(auth.challenges, of: config.challenge_type)
    |> result.replace_error(NoChallengeFound(auth.challenges)),
  )

  let domain = auth.identifier.value

  use _ <- result.try(deploy_challenge(
    config:,
    store:,
    key: registered_key,
    challenge:,
    domain:,
  ))

  Ok(#(ctx, challenge))
}

fn deploy_challenge(
  config config: Config,
  store store: process.Subject(challenge_store.Message),
  key key: acumen.RegisteredKey,
  challenge challenge: Challenge,
  domain domain: String,
) -> Result(Nil, AcmeClientError) {
  case config.challenge_type {
    challenge.Http01 -> deploy_http01(store, key, challenge)
    challenge.Dns01 -> deploy_dns01(key, challenge, domain)
    challenge.DnsAccount01 -> deploy_dns_account01(key, challenge, domain)
    challenge.DnsPersist01 -> deploy_dns_persist01(key, challenge, domain)
    challenge.TlsAlpn01 -> Error(UnsupportedChallengeType("tls-alpn-01"))
  }
}

fn deploy_http01(
  store: process.Subject(challenge_store.Message),
  registered_key: acumen.RegisteredKey,
  challenge: Challenge,
) -> Result(Nil, AcmeClientError) {
  use key_auth <- result.try(
    challenge.key_authorization(challenge, registered_key)
    |> result.map_error(AcmeError),
  )

  use token <- result.try(
    challenge.token(challenge)
    |> result.replace_error(AcmeError(acumen.InvalidChallenge("missing token"))),
  )

  challenge_store.store(store, token, key_auth)
  io.println("  Challenge token: " <> token)
  io.println("  Challenge deployed")

  Ok(Nil)
}

fn deploy_dns01(
  registered_key: acumen.RegisteredKey,
  challenge: Challenge,
  domain: String,
) -> Result(Nil, AcmeClientError) {
  use key_auth <- result.try(
    challenge.key_authorization(challenge, registered_key)
    |> result.map_error(AcmeError),
  )

  use txt_value <- result.try(
    challenge.dns01_txt_record(key_auth)
    |> result.map_error(AcmeError),
  )

  prompt_for_dns_record("_acme-challenge." <> domain, txt_value)

  Ok(Nil)
}

fn deploy_dns_account01(
  registered_key: acumen.RegisteredKey,
  challenge: Challenge,
  domain: String,
) -> Result(Nil, AcmeClientError) {
  use key_auth <- result.try(
    challenge.key_authorization(challenge, registered_key)
    |> result.map_error(AcmeError),
  )

  use #(record_name, txt_value) <- result.try(
    challenge.dns_account01_txt_record(
      for: domain,
      account_url: registered_key.kid,
      key_authorization: key_auth,
    )
    |> result.map_error(AcmeError),
  )

  prompt_for_dns_record(record_name, txt_value)

  Ok(Nil)
}

fn deploy_dns_persist01(
  registered_key: acumen.RegisteredKey,
  challenge: Challenge,
  domain: String,
) -> Result(Nil, AcmeClientError) {
  use issuers <- result.try(
    challenge.issuer_domain_names(challenge)
    |> result.replace_error(
      AcmeError(acumen.InvalidChallenge("missing issuer domain names")),
    ),
  )
  use issuer <- result.try(
    list.first(issuers)
    |> result.replace_error(
      AcmeError(acumen.InvalidChallenge("No issuer domain names provided")),
    ),
  )
  let txt_value =
    challenge.dns_persist01_txt_record(
      issuer: issuer,
      account_url: registered_key.kid,
    )

  prompt_for_dns_record("_validation-persist." <> domain, txt_value)

  Ok(Nil)
}

fn trigger_validation(
  ctx: acumen.Context,
  registered_key: acumen.RegisteredKey,
  challenge: Challenge,
) -> Result(acumen.Context, AcmeClientError) {
  io.println("[Validation] Triggering challenge validation...")
  use #(resp, ctx) <- result.try(
    acumen.execute(
      ctx,
      build: validate_challenge.build(challenge.url, _, registered_key),
      send: httpc.send,
    )
    |> result.map_error(ExecuteError),
  )

  use _ <- result.try(
    validate_challenge.response(resp)
    |> result.map_error(AcmeError),
  )

  io.println("  Validation triggered")
  Ok(ctx)
}

fn wait_for_ready(
  ctx: acumen.Context,
  registered_key: acumen.RegisteredKey,
  acme_order: Order,
) -> Result(#(acumen.Context, Order, ec.PrivateKey), AcmeClientError) {
  io.println("[Ready] Waiting for order to become ready...")
  do_wait_for_ready(ctx, registered_key, acme_order, 0, option.None)
}

fn do_wait_for_ready(
  ctx: acumen.Context,
  registered_key: acumen.RegisteredKey,
  acme_order: Order,
  attempts: Int,
  retry_after: Option(Duration),
) -> Result(#(acumen.Context, Order, ec.PrivateKey), AcmeClientError) {
  use poll <- result.try(poll_order(
    acme_order.url,
    ctx,
    registered_key,
    attempts,
    retry_after,
    "Max polling attempts reached",
  ))

  case poll.order.status {
    order.Ready -> {
      io.println("  Order is ready for finalization")
      io.println("[Finalize] Generating certificate key...")
      let cert_key = storage.generate_certificate_key()
      io.println("  Certificate key generated (EC P-256)")
      Ok(#(poll.ctx, poll.order, cert_key))
    }
    order.Invalid -> Error(OrderNotReady("Order became invalid"))
    order.Pending | order.Processing | order.Valid(_) ->
      do_wait_for_ready(
        poll.ctx,
        registered_key,
        acme_order,
        attempts + 1,
        poll.next_retry_after,
      )
  }
}

fn finalize(
  ctx: acumen.Context,
  registered_key: acumen.RegisteredKey,
  acme_order: Order,
  cert_key: ec.PrivateKey,
) -> Result(#(acumen.Context, Url), AcmeClientError) {
  io.println("[Finalize] Submitting CSR...")
  use csr <- result.try(
    order.to_ec_csr(acme_order, cert_key)
    |> result.replace_error(CsrGenerationError),
  )

  use #(resp, ctx) <- result.try(
    acumen.execute(
      ctx,
      build: finalize_order.build(
        acme_order.finalize_url,
        _,
        registered_key,
        csr:,
      ),
      send: httpc.send,
    )
    |> result.map_error(ExecuteError),
  )

  use finalized <- result.try(
    finalize_order.response(resp, acme_order.url)
    |> result.map_error(AcmeError),
  )

  io.println("  Order finalized")

  case finalized.status {
    order.Valid(cert_url) -> {
      io.println("  Certificate ready")
      Ok(#(ctx, cert_url))
    }
    order.Invalid ->
      Error(OrderNotReady("Order became invalid after finalization"))
    order.Pending | order.Ready | order.Processing -> {
      io.println("  Waiting for certificate to be issued...")
      wait_for_certificate(ctx, registered_key, acme_order.url, 0, option.None)
    }
  }
}

fn wait_for_certificate(
  ctx: acumen.Context,
  registered_key: acumen.RegisteredKey,
  order_url: Url,
  attempts: Int,
  retry_after: Option(Duration),
) -> Result(#(acumen.Context, Url), AcmeClientError) {
  use poll <- result.try(poll_order(
    order_url,
    ctx,
    registered_key,
    attempts,
    retry_after,
    "Max polling attempts reached for certificate",
  ))

  case poll.order.status {
    order.Valid(cert_url) -> {
      io.println("  Certificate ready")
      Ok(#(poll.ctx, cert_url))
    }
    order.Invalid -> Error(OrderNotReady("Order became invalid"))
    order.Pending | order.Ready | order.Processing ->
      wait_for_certificate(
        poll.ctx,
        registered_key,
        order_url,
        attempts + 1,
        poll.next_retry_after,
      )
  }
}

fn download_certificate(
  config: Config,
  ctx: acumen.Context,
  registered_key: acumen.RegisteredKey,
  cert_url: Url,
  cert_key: ec.PrivateKey,
) -> Result(Nil, AcmeClientError) {
  io.println("[Certificate] Downloading certificate...")
  use #(resp, ctx) <- result.try(
    acumen.execute(
      ctx,
      build: fetch_certificate.build(cert_url, _, registered_key),
      send: httpc.send,
    )
    |> result.map_error(ExecuteError),
  )

  use certificate_pem <- result.try(
    fetch_certificate.response(resp)
    |> result.map_error(AcmeError),
  )
  io.println("  Certificate downloaded")
  io.println("[Certificate] Writing certificate and key to disk...")

  use _ <- result.try(
    storage.write_certificate_files(
      config.cert_path,
      config.key_path,
      certificate_pem,
      cert_key,
    )
    |> result.map_error(StorageError),
  )

  io.println("  Files written successfully")
  io.println("  - Certificate: " <> config.cert_path)
  io.println("  - Private key: " <> config.key_path)

  log_renewal_info(ctx.directory, certificate_pem)

  Ok(Nil)
}

fn poll_order(
  order_url: Url,
  ctx: acumen.Context,
  registered_key: acumen.RegisteredKey,
  attempts: Int,
  retry_after: Option(Duration),
  max_attempts_message: String,
) -> Result(PollResult, AcmeClientError) {
  use <- bool.guard(
    when: attempts >= 30,
    return: Error(OrderNotReady(max_attempts_message)),
  )

  let sleep_ms =
    retry_after
    |> option.lazy_unwrap(fn() { exponential_backoff(attempts) })
    |> duration.to_milliseconds
    |> int.max(0)
  process.sleep(sleep_ms)

  use #(resp, ctx) <- result.try(
    acumen.execute(
      ctx,
      build: fetch_order.build(order_url, _, registered_key),
      send: httpc.send,
    )
    |> result.map_error(ExecuteError),
  )

  let next_retry_after =
    acumen.retry_after(resp)
    |> result.map(fn(retry_after) {
      case retry_after {
        acumen.RetryAfterSeconds(seconds) -> duration.seconds(seconds)
        acumen.RetryAfterTimestamp(ts) ->
          timestamp.difference(timestamp.system_time(), ts)
      }
    })
    |> option.from_result

  use acme_order <- result.try(
    fetch_order.response(resp, order_url)
    |> result.map_error(AcmeError),
  )

  io.println("  Order status: " <> order_status_to_string(acme_order.status))
  Ok(PollResult(order: acme_order, ctx:, next_retry_after:))
}

fn dns_record_exists(name: String, expected_value: String) -> Bool {
  lookup_txt(name)
  |> list.any(fn(record) { record == expected_value })
}

fn prompt_for_dns_record(record_name: String, txt_value: String) -> Nil {
  case dns_record_exists(record_name, txt_value) {
    True -> io.println("  DNS TXT record already in place")
    False -> {
      io.println("")
      io.println("  Please create the following DNS TXT record:")
      io.println("")
      io.println("    " <> record_name <> "  TXT  \"" <> txt_value <> "\"")
      io.println("")
      let _ = get_line("  Press Enter when the record is in place...")
      wait_for_dns_propagation(record_name, txt_value, 0)
    }
  }
  io.println("  Proceeding with validation")
}

fn wait_for_dns_propagation(
  record_name: String,
  expected_value: String,
  attempts: Int,
) -> Nil {
  use <- bool.guard(
    when: dns_record_exists(record_name, expected_value),
    return: io.println("  DNS TXT record verified"),
  )
  use <- bool.guard(
    when: attempts >= 60,
    return: io.println(
      "  WARNING: DNS record not detected after 5 minutes, proceeding anyway",
    ),
  )
  case attempts {
    0 ->
      io.println("  Waiting for DNS propagation (checking every 5 seconds)...")
    _ -> Nil
  }
  process.sleep(5000)
  wait_for_dns_propagation(record_name, expected_value, attempts + 1)
}

fn fetch_directory(url: String) -> Result(acumen.Directory, AcmeClientError) {
  use req <- result.try(
    request.to(url)
    |> result.replace_error(InvalidDirectoryUrl),
  )
  use resp <- result.try(
    httpc.send(req)
    |> result.map_error(HttpError),
  )
  acumen.directory(resp)
  |> result.map_error(AcmeError)
}

fn get_nonce(directory: acumen.Directory) -> Result(String, AcmeClientError) {
  let nonce_req = nonce.build(directory)
  use resp <- result.try(
    httpc.send(nonce_req)
    |> result.map_error(HttpError),
  )
  nonce.response(resp)
  |> result.map_error(AcmeError)
}

fn log_renewal_info(directory: acumen.Directory, certificate_pem: String) -> Nil {
  let result = {
    use cert_id <- result.try(
      certificate.cert_id_from_pem(certificate_pem)
      |> result.replace_error(Nil),
    )
    use req <- result.try(
      fetch_renewal_info.build(directory, cert_id)
      |> result.replace_error(Nil),
    )
    use resp <- result.try(
      httpc.send(req)
      |> result.replace_error(Nil),
    )

    fetch_renewal_info.response(resp)
    |> result.replace_error(Nil)
  }

  case result {
    Ok(info) -> {
      let start =
        timestamp.to_rfc3339(info.suggested_window.start, calendar.utc_offset)
      let end =
        timestamp.to_rfc3339(info.suggested_window.end, calendar.utc_offset)
      io.println("  Renewal info: suggested window " <> start <> " to " <> end)
      case info.explanation_url {
        option.Some(url) ->
          io.println("  Explanation URL: " <> uri.to_string(url))
        option.None -> Nil
      }
    }
    Error(_) -> io.println("  Renewal info not available")
  }
}

fn order_status_to_string(status: order.Status) -> String {
  case status {
    order.Pending -> "pending"
    order.Ready -> "ready"
    order.Processing -> "processing"
    order.Valid(_) -> "valid"
    order.Invalid -> "invalid"
  }
}

fn exponential_backoff(attempts: Int) -> Duration {
  let max_seconds = 128
  let seconds = case attempts {
    0 -> 0
    n -> int.min(int.bitwise_shift_left(1, n), max_seconds)
  }
  duration.seconds(seconds)
}
