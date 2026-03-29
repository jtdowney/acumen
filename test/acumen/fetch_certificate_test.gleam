import acumen
import acumen/fetch_certificate
import acumen/url
import gleam/http
import gleam/http/request
import support/fixtures

pub fn build_creates_post_as_get_request_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(url) = url.from_string("https://example.com/cert/123")

  let assert Ok(req) = fetch_certificate.build(url, ctx, key)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/cert/123"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"

  let assert Ok(accept) = request.get_header(req, "accept")
  assert accept == "application/pem-certificate-chain"
}

pub fn response_returns_pem_body_and_updated_context_test() {
  let pem_body =
    "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
  let resp = fixtures.nonce_response(200, "new-nonce", pem_body)

  let assert Ok(certificate) = fetch_certificate.response(resp)

  assert certificate == pem_body
}

pub fn response_rejects_unexpected_status_test() {
  let resp = fixtures.nonce_response(403, "new-nonce", "forbidden")

  let assert Error(acumen.InvalidResponse(_)) = fetch_certificate.response(resp)
}
