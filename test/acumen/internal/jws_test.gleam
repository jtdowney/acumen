import acumen/internal/jws
import acumen/url
import birdie
import gleam/dynamic/decode
import gleam/json
import gleam/result
import gose/jwk
import kryptos/ec
import kryptos/eddsa
import support/fixtures

pub fn sign_with_kid_protected_header_snapshot_test() {
  let key = jwk.generate_ec(ec.P256)
  let assert Ok(kid) = url.from_string("https://example.com/acct/123")
  let payload = json.object([]) |> json.to_string
  let nonce = "test-nonce-value"
  let assert Ok(url) = url.from_string("https://example.com/acme/new-order")

  let assert Ok(signed) = jws.sign_with_kid(key, kid:, payload:, nonce:, url:)

  let assert Ok(protected) = fixtures.extract_protected_header(signed)

  let assert Ok(header) = decode_protected_header(protected)
  let normalized =
    json.object([
      #("alg", json.string(header.alg)),
      #("kid", json.string(header.kid)),
      #("nonce", json.string(header.nonce)),
      #("url", json.string(header.url)),
    ])
    |> json.to_string

  birdie.snap(normalized, "JWS with kid protected header")
}

pub fn sign_with_jwk_has_correct_structure_test() {
  let key = jwk.generate_ec(ec.P256)
  let payload = json.object([]) |> json.to_string
  let nonce = "test-nonce-value"
  let assert Ok(url) = url.from_string("https://example.com/acme/new-account")

  let assert Ok(signed) = jws.sign_with_jwk(key, payload:, nonce:, url:)

  let assert Ok(protected) = fixtures.extract_protected_header(signed)

  let jwk_decoder = {
    use kty <- decode.field("kty", decode.string)
    use crv <- decode.field("crv", decode.string)
    decode.success(#(kty, crv))
  }
  let header_decoder = {
    use alg <- decode.field("alg", decode.string)
    use nonce_val <- decode.field("nonce", decode.string)
    use url_val <- decode.field("url", decode.string)
    use jwk_val <- decode.field("jwk", jwk_decoder)
    decode.success(#(alg, nonce_val, url_val, jwk_val))
  }
  let assert Ok(#(alg, nonce_val, url_val, #(kty, crv))) =
    json.parse(protected, header_decoder)

  assert alg == "ES256"
  assert nonce_val == "test-nonce-value"
  assert url_val == "https://example.com/acme/new-account"
  assert kty == "EC"
  assert crv == "P-256"
}

pub fn sign_with_jwk_rejects_symmetric_key_test() {
  let mac_key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
  let assert Ok(key) = jwk.from_octet_bits(mac_key)

  let assert Ok(url) = url.from_string("https://example.com/url")
  let assert Error(_) =
    jws.sign_with_jwk(key, payload: "{}", nonce: "nonce", url:)
}

pub fn sign_eab_creates_valid_jws_structure_test() {
  let mac_key = <<
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
  >>
  let kid = "test-key-id"
  let payload =
    json.object([
      #("kty", json.string("EC")),
      #("crv", json.string("P-256")),
      #("x", json.string("test")),
      #("y", json.string("test")),
    ])
    |> json.to_string
  let assert Ok(url) = url.from_string("https://example.com/acme/new-account")

  let assert Ok(signed_json) = jws.sign_eab(mac_key, kid:, payload:, url:)

  let signed = json.to_string(signed_json)

  let fields_decoder = {
    use _ <- decode.field("protected", decode.string)
    use _ <- decode.field("payload", decode.string)
    use _ <- decode.field("signature", decode.string)
    decode.success(Nil)
  }
  let assert Ok(Nil) = json.parse(signed, fields_decoder)

  let assert Ok(protected) = fixtures.extract_protected_header(signed)
  birdie.snap(protected, "EAB JWS protected header")
}

pub fn sign_key_change_inner_has_no_nonce_test() {
  let new_key = jwk.generate_ec(ec.P256)
  let payload = json.object([]) |> json.to_string
  let assert Ok(url) = url.from_string("https://example.com/acme/key-change")

  let assert Ok(signed_json) =
    jws.sign_key_change_inner(new_key, payload:, url:)

  let signed = json.to_string(signed_json)
  let assert Ok(protected) = fixtures.extract_protected_header(signed)

  let has_nonce_decoder = {
    use _ <- decode.field("nonce", decode.string)
    decode.success(Nil)
  }
  let assert Error(_) = json.parse(protected, has_nonce_decoder)

  let key_change_decoder = {
    use alg <- decode.field("alg", decode.string)
    use url <- decode.field("url", decode.string)
    decode.success(#(alg, url))
  }
  let assert Ok(#(_, decoded_url)) = json.parse(protected, key_change_decoder)
  assert decoded_url == "https://example.com/acme/key-change"
}

pub fn sign_with_kid_rejects_symmetric_key_test() {
  let mac_key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
  let assert Ok(key) = jwk.from_octet_bits(mac_key)
  let assert Ok(kid) = url.from_string("https://example.com/acct/123")
  let assert Ok(url) = url.from_string("https://example.com/acme/test")
  let assert Error(_) =
    jws.sign_with_kid(key, kid:, payload: "{}", nonce: "nonce", url:)
}

type ProtectedHeader {
  ProtectedHeader(alg: String, kid: String, nonce: String, url: String)
}

fn protected_header_decoder() -> decode.Decoder(ProtectedHeader) {
  use alg <- decode.field("alg", decode.string)
  use kid <- decode.field("kid", decode.string)
  use nonce <- decode.field("nonce", decode.string)
  use url <- decode.field("url", decode.string)
  decode.success(ProtectedHeader(alg:, kid:, nonce:, url:))
}

fn decode_protected_header(json_str: String) -> Result(ProtectedHeader, Nil) {
  json.parse(json_str, protected_header_decoder())
  |> result.replace_error(Nil)
}

fn extract_alg(signed: String) -> String {
  let assert Ok(protected) = fixtures.extract_protected_header(signed)
  let assert Ok(alg) = json.parse(protected, decode.at(["alg"], decode.string))
  alg
}

pub fn sign_with_jwk_ec_p384_selects_es384_test() {
  let key = jwk.generate_ec(ec.P384)
  let assert Ok(url) = url.from_string("https://example.com/acme/test")

  let assert Ok(signed) =
    jws.sign_with_jwk(key, payload: "{}", nonce: "nonce", url:)
  assert extract_alg(signed) == "ES384"
}

pub fn sign_with_jwk_ec_p521_selects_es512_test() {
  let key = jwk.generate_ec(ec.P521)
  let assert Ok(url) = url.from_string("https://example.com/acme/test")

  let assert Ok(signed) =
    jws.sign_with_jwk(key, payload: "{}", nonce: "nonce", url:)
  assert extract_alg(signed) == "ES512"
}

pub fn sign_with_jwk_rsa_selects_rs256_test() {
  let key = fixtures.test_rsa_jwk()
  let assert Ok(url) = url.from_string("https://example.com/acme/test")

  let assert Ok(signed) =
    jws.sign_with_jwk(key, payload: "{}", nonce: "nonce", url:)
  assert extract_alg(signed) == "RS256"
}

pub fn sign_with_jwk_rejects_secp256k1_test() {
  let key = jwk.generate_ec(ec.Secp256k1)
  let assert Ok(url) = url.from_string("https://example.com/acme/test")

  let assert Error(_) =
    jws.sign_with_jwk(key, payload: "{}", nonce: "nonce", url:)
}

pub fn sign_with_jwk_eddsa_selects_eddsa_test() {
  let key = jwk.generate_eddsa(eddsa.Ed25519)
  let assert Ok(url) = url.from_string("https://example.com/acme/test")

  let assert Ok(signed) =
    jws.sign_with_jwk(key, payload: "{}", nonce: "nonce", url:)
  assert extract_alg(signed) == "EdDSA"
}
