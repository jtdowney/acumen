import acumen
import acumen/authorization
import acumen/deactivate_authorization
import acumen/url
import birdie
import gleam/http
import gleam/http/request
import gleam/json
import support/fixtures

pub fn build_creates_post_to_authorization_url_test() {
  let context = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(authz_url) = url.from_string("https://example.com/authz/456")

  let assert Ok(req) = deactivate_authorization.build(authz_url, context, key)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/authz/456"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn build_payload_snapshot_test() {
  let context = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(authz_url) = url.from_string("https://example.com/authz/456")

  let assert Ok(req) = deactivate_authorization.build(authz_url, context, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "deactivate authorization payload")
}

pub fn response_parses_deactivated_authorization_test() {
  let assert Ok(authz_url) = url.from_string("https://example.com/authz/456")
  let body =
    json.object([
      #("status", json.string("deactivated")),
      #(
        "identifier",
        json.object([
          #("type", json.string("dns")),
          #("value", json.string("example.com")),
        ]),
      ),
      #("challenges", json.preprocessed_array([])),
    ])
    |> json.to_string

  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(authz) = deactivate_authorization.response(resp, authz_url)

  assert authz.status == authorization.Deactivated
  assert authz.identifier == acumen.DnsIdentifier("example.com")
}

pub fn response_rejects_unexpected_status_test() {
  let assert Ok(authz_url) = url.from_string("https://example.com/authz/456")
  let resp = fixtures.nonce_response(403, "new-nonce", "{}")

  let assert Error(acumen.InvalidResponse(_)) =
    deactivate_authorization.response(resp, authz_url)
}

pub fn response_rejects_malformed_json_body_test() {
  let assert Ok(authz_url) = url.from_string("https://example.com/authz/456")
  let resp = fixtures.nonce_response(200, "new-nonce", "not json")

  let assert Error(acumen.JsonParseError(_)) =
    deactivate_authorization.response(resp, authz_url)
}
