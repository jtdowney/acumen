import acumen
import acumen/fetch_order
import acumen/order
import acumen/url
import gleam/http
import gleam/http/request
import gleam/json
import gleam/option
import gleam/time/timestamp
import support/fixtures

pub fn build_creates_post_as_get_request_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(url) = url.from_string("https://example.com/order/123")

  let assert Ok(req) = fetch_order.build(url, ctx, key)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/order/123"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn response_parses_order_with_all_fields_test() {
  let assert Ok(url) = url.from_string("https://example.com/order/123")
  let body =
    json.object([
      #("status", json.string("valid")),
      #(
        "identifiers",
        json.preprocessed_array([
          json.object([
            #("type", json.string("dns")),
            #("value", json.string("example.com")),
          ]),
        ]),
      ),
      #(
        "authorizations",
        json.array(["https://example.com/authz/1"], json.string),
      ),
      #("finalize", json.string("https://example.com/finalize/1")),
      #("certificate", json.string("https://example.com/cert/1")),
      #("expires", json.string("2024-12-31T23:59:59Z")),
      #("profile", json.string("codesigning")),
    ])
    |> json.to_string
  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(ord) = fetch_order.response(resp, url)

  assert ord.url == url
  let assert Ok(expected_cert) = url.from_string("https://example.com/cert/1")
  assert ord.status == order.Valid(expected_cert)
  assert ord.identifiers == [acumen.DnsIdentifier("example.com")]
  let assert Ok(expected_expires) =
    timestamp.parse_rfc3339("2024-12-31T23:59:59Z")
  assert ord.expires == option.Some(expected_expires)
  assert ord.profile == option.Some("codesigning")
}

pub fn response_uses_provided_url_not_header_test() {
  let assert Ok(url) = url.from_string("https://example.com/order/456")
  let body =
    json.object(fixtures.minimal_order_fields(["example.com"]))
    |> json.to_string
  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(ord) = fetch_order.response(resp, url)

  assert ord.url == url
}

pub fn response_parses_minimal_order_test() {
  let assert Ok(url) = url.from_string("https://example.com/order/123")
  let body =
    json.object(fixtures.minimal_order_fields(["example.com"]))
    |> json.to_string
  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(ord) = fetch_order.response(resp, url)

  assert ord.status == order.Pending
  assert ord.identifiers == [acumen.DnsIdentifier("example.com")]
  assert ord.profile == option.None
}

pub fn response_rejects_unexpected_status_test() {
  let assert Ok(url) = url.from_string("https://example.com/order/123")
  let resp = fixtures.nonce_response(403, "new-nonce", "{}")

  let assert Error(acumen.InvalidResponse(_)) = fetch_order.response(resp, url)
}

pub fn response_rejects_malformed_json_body_test() {
  let assert Ok(url) = url.from_string("https://example.com/order/123")
  let resp = fixtures.nonce_response(200, "new-nonce", "not json")

  let assert Error(acumen.JsonParseError(_)) = fetch_order.response(resp, url)
}
