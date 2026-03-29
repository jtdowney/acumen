import acme_example/challenge_store
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/option
import gleam/otp/static_supervisor
import gleam/otp/supervision
import mist
import wisp
import wisp/wisp_mist

pub fn child(
  port: Int,
  domain: String,
  https_port: Int,
  store_name: process.Name(challenge_store.Message),
) -> supervision.ChildSpecification(static_supervisor.Supervisor) {
  let store = process.named_subject(store_name)
  handle_request(_, store, domain, https_port)
  |> wisp_mist.handler(wisp.random_string(64))
  |> mist.new
  |> mist.bind("0.0.0.0")
  |> mist.port(port)
  |> mist.supervised
}

fn handle_request(
  req: wisp.Request,
  store: process.Subject(challenge_store.Message),
  domain: String,
  https_port: Int,
) -> wisp.Response {
  use <- wisp.log_request(req)

  case wisp.path_segments(req) {
    [".well-known", "acme-challenge", token] -> handle_challenge(store, token)
    _ -> {
      let port_suffix = case https_port {
        443 -> ""
        p -> ":" <> int.to_string(p)
      }
      let query_suffix =
        req.query
        |> option.map(fn(q) { "?" <> q })
        |> option.unwrap("")
      let url = "https://" <> domain <> port_suffix <> req.path <> query_suffix
      wisp.redirect(to: url)
    }
  }
}

fn handle_challenge(
  store: process.Subject(challenge_store.Message),
  token: String,
) -> wisp.Response {
  case challenge_store.lookup(store, token) {
    Ok(key_auth) -> {
      io.println("Serving challenge for token: " <> token)
      wisp.ok()
      |> wisp.string_body(key_auth)
    }
    Error(Nil) -> wisp.not_found()
  }
}
