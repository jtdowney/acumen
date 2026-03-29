import acumen
import acumen/account.{type Account}
import acumen/challenge
import acumen/create_order
import acumen/fetch_authorization
import acumen/fetch_order
import acumen/nonce
import acumen/order.{type Order}
import acumen/register_account
import acumen/validate_challenge
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/httpc
import gleam/json
import gleam/list
import gleam/result
import gose/jwk
import kryptos/ec
import kryptos/hash
import kryptos/x509
import kryptos/x509/csr

pub const pebble_url = "https://localhost:14000"

pub const challtestsrv_url = "http://localhost:8055"

const max_poll_retries = 100

@external(erlang, "timer", "sleep")
pub fn sleep(ms: Int) -> Nil

pub fn http_config() -> httpc.Configuration {
  httpc.configure()
  |> httpc.verify_tls(False)
}

pub fn send(
  req: request.Request(String),
) -> Result(response.Response(String), httpc.HttpError) {
  httpc.dispatch(http_config(), req)
}

pub fn fetch_directory() -> acumen.Directory {
  let assert Ok(req) = request.to(pebble_url <> "/dir")
  let assert Ok(resp) = send(req)
  let assert Ok(directory) = acumen.directory(resp)
  directory
}

pub fn fetch_nonce(directory: acumen.Directory) -> String {
  let req = nonce.build(directory)
  let assert Ok(resp) = send(req)
  let assert Ok(nonce) = nonce.response(resp)
  nonce
}

pub fn setup_context() -> acumen.Context {
  let directory = fetch_directory()
  let initial_nonce = fetch_nonce(directory)
  acumen.Context(directory:, nonce: initial_nonce)
}

pub fn setup_registered_account() -> #(
  Account,
  acumen.RegisteredKey,
  acumen.Context,
) {
  let ctx = setup_context()
  let unregistered = generate_key()
  register_account(ctx, unregistered)
}

pub fn add_http01_challenge(token: String, content: String) -> Nil {
  let body =
    json.object([
      #("token", json.string(token)),
      #("content", json.string(content)),
    ])
    |> json.to_string

  let assert Ok(req) = request.to(challtestsrv_url <> "/add-http01")
  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_body(body)
    |> request.set_header("content-type", "application/json")
  let assert Ok(_) = send(req)
  Nil
}

pub fn add_dns01_challenge(domain: String, txt_value: String) -> Nil {
  let body =
    json.object([
      #("host", json.string("_acme-challenge." <> domain <> ".")),
      #("value", json.string(txt_value)),
    ])
    |> json.to_string

  let assert Ok(req) = request.to(challtestsrv_url <> "/set-txt")
  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_body(body)
    |> request.set_header("content-type", "application/json")
  let assert Ok(_) = send(req)
  Nil
}

pub fn generate_csr(domains: List(String)) -> BitArray {
  let #(csr_der, _cert_key) = generate_csr_with_key(domains)
  csr_der
}

pub fn generate_csr_with_key(domains: List(String)) -> #(BitArray, jwk.Jwk) {
  let assert [first_domain, ..] = domains

  let #(private_key, _) = ec.generate_key_pair(ec.P256)

  let subject = x509.name([x509.cn(first_domain)])

  let assert Ok(builder) =
    list.try_fold(domains, csr.new(), fn(builder, domain) {
      csr.with_dns_name(builder, domain)
    })
    |> result.map(csr.with_subject(_, subject))

  let assert Ok(signed_csr) =
    csr.sign_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(pem) = ec.to_pem(private_key)
  let assert Ok(cert_jwk) = jwk.from_pem(pem)

  #(csr.to_der(signed_csr), cert_jwk)
}

pub fn generate_key() -> acumen.UnregisteredKey {
  let key = jwk.generate_ec(ec.P256)
  acumen.UnregisteredKey(key)
}

pub fn register_account(
  ctx: acumen.Context,
  unregistered: acumen.UnregisteredKey,
) -> #(Account, acumen.RegisteredKey, acumen.Context) {
  let reg =
    register_account.request()
    |> register_account.contacts(["mailto:test@example.com"])
    |> register_account.agree_to_terms

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: register_account.build(reg, _, unregistered),
      send:,
    )

  let assert Ok(#(account, registered_key)) =
    register_account.response(resp, unregistered)

  #(account, registered_key, ctx)
}

pub fn complete_http01_order(
  ctx: acumen.Context,
  registered_key: acumen.RegisteredKey,
  domain: String,
) -> #(Order, acumen.Context) {
  let assert Ok(ord) =
    create_order.request(identifiers: [acumen.DnsIdentifier(domain)])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send:,
    )

  let assert Ok(created_order) = create_order.response(resp)
  let assert [auth_url, ..] = created_order.authorizations

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: acumen.build_fetch(auth_url, _, registered_key),
      send:,
    )

  let assert Ok(auth) = fetch_authorization.response(resp, auth_url)
  let assert Ok(http_challenge) =
    challenge.find_by_type(auth.challenges, of: challenge.Http01)
  let assert Ok(token) = challenge.token(http_challenge)

  let assert Ok(key_auth) =
    challenge.key_authorization(http_challenge, registered_key)
  add_http01_challenge(token, key_auth)

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: validate_challenge.build(http_challenge.url, _, registered_key),
      send:,
    )

  let assert Ok(_updated_challenge) = validate_challenge.response(resp)

  let #(ready_order, ctx) =
    poll_order_until_ready(ctx, created_order, registered_key)

  assert ready_order.status == order.Ready

  #(ready_order, ctx)
}

pub fn poll_order_until_ready(
  ctx: acumen.Context,
  ord: Order,
  registered_key: acumen.RegisteredKey,
) -> #(Order, acumen.Context) {
  poll_order_until(ctx, ord, registered_key, max_poll_retries, fn(s) {
    s == order.Ready
  })
}

pub fn poll_order_until_valid(
  ctx: acumen.Context,
  ord: Order,
  registered_key: acumen.RegisteredKey,
) -> #(Order, acumen.Context) {
  poll_order_until(ctx, ord, registered_key, max_poll_retries, fn(s) {
    case s {
      order.Valid(_) -> True
      order.Pending | order.Ready | order.Processing | order.Invalid -> False
    }
  })
}

fn poll_order_until(
  ctx: acumen.Context,
  ord: Order,
  registered_key: acumen.RegisteredKey,
  retries_remaining: Int,
  matches: fn(order.Status) -> Bool,
) -> #(Order, acumen.Context) {
  case matches(ord.status) {
    True -> #(ord, ctx)
    False if ord.status == order.Invalid -> panic as "order became invalid"
    False if retries_remaining <= 0 ->
      panic as "poll_order_until exhausted max retries (100 attempts, ~10s)"
    False -> {
      sleep(100)
      let assert Ok(#(resp, ctx)) =
        acumen.execute(
          ctx,
          build: acumen.build_fetch(ord.url, _, registered_key),
          send:,
        )
      let assert Ok(updated_order) = fetch_order.response(resp, ord.url)
      poll_order_until(
        ctx,
        updated_order,
        registered_key,
        retries_remaining - 1,
        matches,
      )
    }
  }
}
