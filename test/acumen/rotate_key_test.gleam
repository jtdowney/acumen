import acumen
import acumen/rotate_key
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/json
import support/fixtures

pub fn build_creates_post_to_key_change_test() {
  let ctx = fixtures.test_context()
  let old_key = fixtures.test_registered_key()
  let new_key = fixtures.test_ec_key()

  let builder = rotate_key.request(new_key)
  let assert Ok(req) = rotate_key.build(builder, ctx, old_key)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/endpoint"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn build_creates_nested_jws_body_test() {
  let ctx = fixtures.test_context()
  let old_key = fixtures.test_registered_key()
  let new_key = fixtures.test_ec_key()

  let builder = rotate_key.request(new_key)
  let assert Ok(req) = rotate_key.build(builder, ctx, old_key)

  let signature_decoder = {
    use signature <- decode.field("signature", decode.string)
    decode.success(signature)
  }

  let assert Ok(outer_sig) = json.parse(req.body, signature_decoder)
  assert outer_sig != ""

  let assert Ok(inner_payload) = fixtures.extract_jws_payload(req.body)
  let assert Ok(inner_sig) = json.parse(inner_payload, signature_decoder)
  assert inner_sig != ""
}

pub fn build_inner_jws_contains_account_and_old_key_test() {
  let ctx = fixtures.test_context()
  let old_key = fixtures.test_registered_key()
  let new_key = fixtures.test_ec_key()

  let builder = rotate_key.request(new_key)
  let assert Ok(req) = rotate_key.build(builder, ctx, old_key)

  let assert Ok(inner_jws) = fixtures.extract_jws_payload(req.body)
  let assert Ok(inner_payload) = fixtures.extract_jws_payload(inner_jws)

  let inner_decoder = {
    use account_val <- decode.field("account", decode.string)
    use old_key_kty <- decode.subfield(["oldKey", "kty"], decode.string)
    decode.success(#(account_val, old_key_kty))
  }
  let assert Ok(#(account_val, old_key_kty)) =
    json.parse(inner_payload, inner_decoder)
  assert account_val == "https://example.com/acct/123"
  assert old_key_kty == "EC"
}

pub fn response_returns_new_registered_key_test() {
  let new_key = fixtures.test_ec_key()
  let old_key = fixtures.test_registered_key()

  let resp = fixtures.nonce_response(200, "new-nonce", "")

  let assert Ok(new_registered_key) =
    rotate_key.response(resp, new_key, old_key)

  assert new_registered_key.kid == old_key.kid
}

pub fn response_rejects_unexpected_status_test() {
  let new_key = fixtures.test_ec_key()
  let old_key = fixtures.test_registered_key()
  let resp = fixtures.nonce_response(403, "new-nonce", "{}")

  let assert Error(acumen.InvalidResponse(_)) =
    rotate_key.response(resp, new_key, old_key)
}
