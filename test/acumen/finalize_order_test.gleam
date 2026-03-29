import acumen
import acumen/finalize_order
import acumen/order
import acumen/url
import birdie
import gleam/http
import gleam/http/request
import gleam/json
import support/fixtures

pub fn build_creates_post_to_finalize_url_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(finalize_url) =
    url.from_string("https://example.com/finalize/123")
  let csr = <<"fake-csr-der-bytes":utf8>>

  let assert Ok(req) = finalize_order.build(finalize_url, ctx, key, csr:)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/finalize/123"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn build_payload_snapshot_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(finalize_url) =
    url.from_string("https://example.com/finalize/123")
  let csr = <<"fake-csr-der-bytes":utf8>>

  let assert Ok(req) = finalize_order.build(finalize_url, ctx, key, csr:)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "finalize order payload")
}

pub fn response_parses_processing_order_test() {
  let assert Ok(order_url) = url.from_string("https://example.com/order/123")
  let body =
    json.object([
      #("status", json.string("processing")),
      #(
        "identifiers",
        fixtures.identifiers_json([acumen.DnsIdentifier("example.com")]),
      ),
      #(
        "authorizations",
        json.array(["https://example.com/authz/1"], json.string),
      ),
      #("finalize", json.string("https://example.com/finalize/1")),
    ])
    |> json.to_string
  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(finalized) = finalize_order.response(resp, order_url)

  assert finalized.status == order.Processing
  assert finalized.identifiers == [acumen.DnsIdentifier("example.com")]
}

pub fn response_rejects_unexpected_status_test() {
  let assert Ok(order_url) = url.from_string("https://example.com/order/123")
  let resp = fixtures.nonce_response(403, "new-nonce", "{}")

  let assert Error(acumen.InvalidResponse(_)) =
    finalize_order.response(resp, order_url)
}

pub fn response_parses_valid_order_with_certificate_test() {
  let assert Ok(order_url) = url.from_string("https://example.com/order/123")
  let body =
    json.object([
      #("status", json.string("valid")),
      #(
        "identifiers",
        fixtures.identifiers_json([acumen.DnsIdentifier("example.com")]),
      ),
      #(
        "authorizations",
        json.array(["https://example.com/authz/1"], json.string),
      ),
      #("finalize", json.string("https://example.com/finalize/1")),
      #("certificate", json.string("https://example.com/cert/1")),
    ])
    |> json.to_string
  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(finalized) = finalize_order.response(resp, order_url)

  let assert Ok(expected_cert) = url.from_string("https://example.com/cert/1")
  assert finalized.status == order.Valid(expected_cert)
}

pub fn response_rejects_malformed_json_body_test() {
  let assert Ok(order_url) = url.from_string("https://example.com/order/123")
  let resp = fixtures.nonce_response(200, "new-nonce", "not json")

  let assert Error(acumen.JsonParseError(_)) =
    finalize_order.response(resp, order_url)
}
