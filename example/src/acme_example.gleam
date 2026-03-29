import acme_example/acme_client
import acme_example/challenge_store
import acme_example/http_server
import acme_example/renewal_manager
import acme_example/utils
import acumen/account
import acumen/challenge
import argv
import clip
import clip/help
import clip/opt
import filepath
import gleam/bit_array
import gleam/erlang/application
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/option
import gleam/otp/actor
import gleam/otp/static_supervisor as supervisor
import gleam/result
import gleam/string
import wisp

const lets_encrypt_staging = "https://acme-staging-v02.api.letsencrypt.org/directory"

pub fn main() -> Nil {
  case run_cli(argv.load()) {
    Ok(config) -> run_with_config(config)
    Error(err) -> {
      io.println_error(err)
      utils.halt(1)
    }
  }
}

fn run_cli(argv: argv.Argv) -> Result(acme_client.Config, String) {
  use command <- result.try(cli())
  clip.help(
    command,
    help.simple("acme_example", "ACME certificate issuance example"),
  )
  |> clip.run(argv.arguments)
}

fn cli() -> Result(clip.Command(acme_client.Config), String) {
  use priv_directory <- result.try(
    application.priv_directory("acme_example")
    |> result.replace_error("could not find priv directory for acme_example"),
  )

  clip.command({
    use domain <- clip.parameter
    use email <- clip.parameter
    use directory_url <- clip.parameter
    use http_port <- clip.parameter
    use https_port <- clip.parameter
    use storage_path <- clip.parameter
    use cert_path <- clip.parameter
    use key_path <- clip.parameter
    use profile <- clip.parameter
    use challenge_type <- clip.parameter
    use eab_key_id <- clip.parameter
    use eab_mac_key <- clip.parameter
    let maybe_eab = parse_eab(eab_key_id, eab_mac_key)

    acme_client.Config(
      domain:,
      email:,
      directory_url:,
      http_port:,
      https_port:,
      storage_path:,
      cert_path:,
      key_path:,
      profile: option.from_result(profile),
      challenge_type:,
      replaces: option.None,
      eab: option.from_result(maybe_eab),
    )
  })
  |> clip.opt(
    opt.new("domain")
    |> opt.help("Domain name to request certificate for"),
  )
  |> clip.opt(opt.new("email") |> opt.help("Contact email for ACME account"))
  |> clip.opt(
    opt.new("directory")
    |> opt.default(lets_encrypt_staging)
    |> opt.help("ACME directory URL"),
  )
  |> clip.opt(
    opt.new("http-port")
    |> opt.int
    |> opt.default(80)
    |> opt.help("HTTP port for challenge server"),
  )
  |> clip.opt(
    opt.new("https-port")
    |> opt.int
    |> opt.default(443)
    |> opt.help("HTTPS port for TLS server"),
  )
  |> clip.opt(
    opt.new("storage-path")
    |> opt.default(filepath.join(priv_directory, "storage"))
    |> opt.help("Storage directory for persistent data"),
  )
  |> clip.opt(
    opt.new("cert-path")
    |> opt.default(filepath.join(priv_directory, "cert.pem"))
    |> opt.help("Output path for certificate"),
  )
  |> clip.opt(
    opt.new("key-path")
    |> opt.default(filepath.join(priv_directory, "key.pem"))
    |> opt.help("Output path for private key"),
  )
  |> clip.opt(
    opt.new("profile")
    |> opt.optional
    |> opt.help("Certificate profile to request"),
  )
  |> clip.opt(
    opt.new("challenge-type")
    |> opt.help(
      "Challenge type: http-01, dns-01, dns-account-01, dns-persist-01",
    )
    |> opt.try_map(parse_challenge_type)
    |> opt.default(challenge.Http01),
  )
  |> clip.opt(
    opt.new("eab-key-id")
    |> opt.optional
    |> opt.help("EAB key ID from the CA (requires --eab-mac-key)"),
  )
  |> clip.opt(
    opt.new("eab-mac-key")
    |> opt.optional
    |> opt.help("EAB MAC key, base64url-encoded (requires --eab-key-id)"),
  )
  |> Ok
}

fn run_with_config(config: acme_client.Config) {
  wisp.configure_logger()

  io.println("ACME Example")
  io.println("============")
  io.println("")
  io.println("acme_client.Config:")
  io.println("  Domain: " <> config.domain)
  io.println("  Email: " <> config.email)
  io.println("  Directory: " <> config.directory_url)
  io.println("  HTTP Port: " <> int.to_string(config.http_port))
  io.println("  HTTPS Port: " <> int.to_string(config.https_port))
  io.println("  Storage Path: " <> config.storage_path)
  io.println("  Certificate Path: " <> config.cert_path)
  io.println("  Key Path: " <> config.key_path)
  case config.profile {
    option.Some(p) -> io.println("  Profile: " <> p)
    option.None -> Nil
  }
  case config.eab {
    option.Some(eab) -> io.println("  EAB Key ID: " <> eab.key_id)
    option.None -> Nil
  }
  io.println(
    "  Challenge Type: " <> challenge_type_to_string(config.challenge_type),
  )
  io.println("")

  case start_services(config) {
    Ok(_) -> Nil
    Error(err) -> {
      io.println_error("Failed to start services: " <> string.inspect(err))
      utils.halt(1)
    }
  }
  io.println("HTTP server started on port " <> int.to_string(config.http_port))
  io.println("")

  process.sleep_forever()
}

fn start_services(
  config: acme_client.Config,
) -> Result(actor.Started(supervisor.Supervisor), actor.StartError) {
  let store_name = process.new_name("challenge_store")

  supervisor.new(supervisor.OneForOne)
  |> supervisor.add(challenge_store.child(store_name))
  |> supervisor.add(http_server.child(
    config.http_port,
    config.domain,
    config.https_port,
    store_name,
  ))
  |> supervisor.add(renewal_manager.child(config, store_name))
  |> supervisor.start
}

fn parse_eab(
  key_id: Result(String, Nil),
  mac_key_b64: Result(String, Nil),
) -> Result(account.ExternalAccountBinding, Nil) {
  case key_id, mac_key_b64 {
    Ok(kid), Ok(mac_b64) ->
      case bit_array.base64_url_decode(mac_b64) {
        Ok(mac_key) -> Ok(account.ExternalAccountBinding(kid, mac_key))
        Error(_) -> {
          io.println_error("Error: --eab-mac-key is not valid base64url")
          utils.halt(1)
        }
      }
    Error(_), Error(_) -> Error(Nil)
    _, _ -> {
      io.println_error(
        "Error: --eab-key-id and --eab-mac-key must both be provided",
      )
      utils.halt(1)
    }
  }
}

fn parse_challenge_type(
  value: String,
) -> Result(challenge.ChallengeType, String) {
  case value {
    "http-01" -> Ok(challenge.Http01)
    "dns-01" -> Ok(challenge.Dns01)
    "dns-account-01" -> Ok(challenge.DnsAccount01)
    "dns-persist-01" -> Ok(challenge.DnsPersist01)
    _ ->
      Error(
        "Unknown challenge type '"
        <> value
        <> "'. Valid types: http-01, dns-01, dns-account-01, dns-persist-01",
      )
  }
}

fn challenge_type_to_string(challenge_type: challenge.ChallengeType) -> String {
  case challenge_type {
    challenge.Http01 -> "http-01"
    challenge.Dns01 -> "dns-01"
    challenge.DnsAccount01 -> "dns-account-01"
    challenge.DnsPersist01 -> "dns-persist-01"
    challenge.TlsAlpn01 -> "tls-alpn-01"
  }
}
