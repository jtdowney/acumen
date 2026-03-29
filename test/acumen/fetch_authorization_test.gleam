import acumen
import acumen/authorization
import acumen/fetch_authorization
import acumen/url.{type Url}
import gleam/http
import gleam/http/request
import gleam/json
import gleam/list
import gleam/option
import support/fixtures

fn test_authz_url() -> Url {
  let assert Ok(authz_url) = url.from_string("https://acme.example/authz/1")
  authz_url
}

pub fn build_creates_post_as_get_request_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()

  let assert Ok(req) = fetch_authorization.build(test_authz_url(), ctx, key)

  assert req.method == http.Post
  assert req.host == "acme.example"
  assert req.path == "/authz/1"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn parses_authorization_response_test() {
  let body =
    json.object([
      #("status", json.string("pending")),
      #(
        "identifier",
        json.object([
          #("type", json.string("dns")),
          #("value", json.string("example.com")),
        ]),
      ),
      #(
        "challenges",
        json.preprocessed_array([
          json.object([
            #("type", json.string("http-01")),
            #("status", json.string("pending")),
            #("url", json.string("https://acme.example/chall/1")),
            #("token", json.string("abc123")),
          ]),
        ]),
      ),
      #("expires", json.string("2024-12-31T23:59:59Z")),
    ])
    |> json.to_string

  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(auth) = fetch_authorization.response(resp, test_authz_url())

  assert auth.status == authorization.Pending
  assert auth.identifier == acumen.DnsIdentifier("example.com")
  assert list.length(auth.challenges) == 1
  assert option.is_some(auth.expires)
}

pub fn response_rejects_unexpected_status_test() {
  let resp = fixtures.nonce_response(403, "new-nonce", "{}")

  let assert Error(acumen.InvalidResponse(_)) =
    fetch_authorization.response(resp, test_authz_url())
}

pub fn response_rejects_malformed_json_body_test() {
  let resp = fixtures.nonce_response(200, "new-nonce", "not json")

  let assert Error(acumen.JsonParseError(_)) =
    fetch_authorization.response(resp, test_authz_url())
}

pub fn response_parses_wildcard_authorization_test() {
  let body =
    json.object([
      #("status", json.string("valid")),
      #(
        "identifier",
        json.object([
          #("type", json.string("dns")),
          #("value", json.string("example.com")),
        ]),
      ),
      #("challenges", json.preprocessed_array([])),
      #("wildcard", json.bool(True)),
    ])
    |> json.to_string

  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(auth) = fetch_authorization.response(resp, test_authz_url())

  assert auth.wildcard
  assert auth.identifier == acumen.DnsIdentifier("example.com")
}
