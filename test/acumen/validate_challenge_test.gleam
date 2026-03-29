import acumen
import acumen/challenge
import acumen/url
import acumen/validate_challenge
import birdie
import gleam/http
import gleam/http/request
import gleam/json
import gleam/option
import support/fixtures

fn make_test_http_challenge() -> challenge.Challenge {
  let assert Ok(chall_url) = url.from_string("https://example.com/chall/1")
  challenge.Http01Challenge(
    url: chall_url,
    status: challenge.Pending,
    token: "test-token",
    validated: option.None,
    error: option.None,
  )
}

pub fn build_creates_post_to_challenge_url_test() {
  let registered = fixtures.test_registered_key()
  let ctx = fixtures.test_context()
  let chall = make_test_http_challenge()

  let assert Ok(req) = validate_challenge.build(chall.url, ctx, registered)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/chall/1"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn build_payload_snapshot_test() {
  let registered = fixtures.test_registered_key()
  let ctx = fixtures.test_context()
  let chall = make_test_http_challenge()

  let assert Ok(req) = validate_challenge.build(chall.url, ctx, registered)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "validate challenge payload")
}

pub fn build_creates_post_for_dns_persist01_challenge_test() {
  let registered = fixtures.test_registered_key()
  let ctx = fixtures.test_context()
  let assert Ok(persist_url) =
    url.from_string("https://example.com/chall/persist")
  let chall =
    challenge.DnsPersist01Challenge(
      url: persist_url,
      status: challenge.Pending,
      validated: option.None,
      error: option.None,
      issuer_domain_names: ["letsencrypt.org"],
    )

  let assert Ok(req) = validate_challenge.build(chall.url, ctx, registered)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/chall/persist"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn response_parses_challenge_response_test() {
  let body =
    json.object([
      #("status", json.string("processing")),
      #("type", json.string("http-01")),
      #("url", json.string("https://example.com/chall/1")),
      #("token", json.string("test-token")),
    ])
    |> json.to_string
  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(chall) = validate_challenge.response(resp)

  assert challenge.status(chall) == challenge.Processing
}

pub fn response_rejects_unexpected_status_test() {
  let resp = fixtures.nonce_response(403, "new-nonce", "{}")

  let assert Error(acumen.InvalidResponse(_)) =
    validate_challenge.response(resp)
}

pub fn response_rejects_malformed_json_body_test() {
  let resp = fixtures.nonce_response(200, "new-nonce", "not json")

  let assert Error(acumen.JsonParseError(_)) = validate_challenge.response(resp)
}

pub fn response_rejects_unknown_challenge_type_test() {
  let body =
    json.object([
      #("status", json.string("valid")),
      #("type", json.string("unknown-99")),
      #("url", json.string("https://example.com/chall/1")),
      #("token", json.string("test-token")),
    ])
    |> json.to_string
  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Error(acumen.JsonParseError(_)) = validate_challenge.response(resp)
}
