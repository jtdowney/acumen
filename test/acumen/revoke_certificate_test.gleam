import acumen
import acumen/revoke_certificate
import birdie
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/json
import gleam/list
import gose/jwk
import kryptos/ec
import support/fixtures

pub fn build_creates_post_to_revoke_cert_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let der_bytes = <<48, 130, 1, 0>>
  let builder = revoke_certificate.request(der_bytes)

  let assert Ok(req) = revoke_certificate.build(builder, ctx, key)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/endpoint"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn build_encodes_certificate_as_base64url_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let der_bytes = <<48, 130, 1, 0>>
  let builder = revoke_certificate.request(der_bytes)

  let assert Ok(req) = revoke_certificate.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "revoke certificate payload")
}

pub fn build_includes_reason_when_set_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let der_bytes = <<48, 130, 1, 0>>
  let builder =
    revoke_certificate.request(der_bytes)
    |> revoke_certificate.reason(revoke_certificate.KeyCompromise)

  let assert Ok(req) = revoke_certificate.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "revoke certificate with reason payload")
}

pub fn build_encodes_all_revocation_reason_codes_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let der_bytes = <<48, 130, 1, 0>>

  let cases = [
    #(revoke_certificate.Unspecified, 0),
    #(revoke_certificate.KeyCompromise, 1),
    #(revoke_certificate.CaCompromise, 2),
    #(revoke_certificate.AffiliationChanged, 3),
    #(revoke_certificate.Superseded, 4),
    #(revoke_certificate.CessationOfOperation, 5),
    #(revoke_certificate.CertificateHold, 6),
    #(revoke_certificate.RemoveFromCrl, 8),
    #(revoke_certificate.PrivilegeWithdrawn, 9),
    #(revoke_certificate.AaCompromise, 10),
  ]

  let reason_decoder = {
    use reason <- decode.field("reason", decode.int)
    decode.success(reason)
  }

  list.each(cases, fn(case_) {
    let #(reason, expected_code) = case_
    let builder =
      revoke_certificate.request(der_bytes)
      |> revoke_certificate.reason(reason)

    let assert Ok(req) = revoke_certificate.build(builder, ctx, key)
    let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
    let assert Ok(code) = json.parse(payload, reason_decoder)
    assert code == expected_code
  })
}

pub fn build_with_certificate_key_creates_post_test() {
  let ctx = fixtures.test_context()
  let cert_key = jwk.generate_ec(ec.P256)
  let der_bytes = <<48, 130, 1, 0>>
  let builder = revoke_certificate.request(der_bytes)

  let assert Ok(req) =
    revoke_certificate.build_with_certificate_key(builder, ctx, cert_key)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/endpoint"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn build_with_certificate_key_encodes_payload_test() {
  let ctx = fixtures.test_context()
  let cert_key = jwk.generate_ec(ec.P256)
  let der_bytes = <<48, 130, 1, 0>>
  let builder = revoke_certificate.request(der_bytes)

  let assert Ok(req) =
    revoke_certificate.build_with_certificate_key(builder, ctx, cert_key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "revoke certificate with certificate key payload")
}

pub fn build_with_certificate_key_uses_jwk_header_test() {
  let ctx = fixtures.test_context()
  let cert_key = jwk.generate_ec(ec.P256)
  let der_bytes = <<48, 130, 1, 0>>
  let builder = revoke_certificate.request(der_bytes)

  let assert Ok(req) =
    revoke_certificate.build_with_certificate_key(builder, ctx, cert_key)

  let assert Ok(header) = fixtures.extract_protected_header(req.body)
  let header_decoder = {
    use jwk_field <- decode.field("jwk", decode.dynamic)
    decode.success(jwk_field)
  }
  let assert Ok(_jwk) = json.parse(header, header_decoder)
}

pub fn response_returns_ok_on_success_test() {
  let resp = fixtures.nonce_response(200, "new-nonce", "")

  let assert Ok(Nil) = revoke_certificate.response(resp)
}

pub fn response_rejects_unexpected_status_test() {
  let resp = fixtures.nonce_response(403, "new-nonce", "")

  let assert Error(acumen.InvalidResponse(_)) =
    revoke_certificate.response(resp)
}
