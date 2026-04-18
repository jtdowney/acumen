import acumen/internal/utils
import acumen/url.{type Url}
import gleam/bit_array
import gleam/json
import gleam/result
import gose
import gose/jose/jwk
import gose/jose/jws
import kryptos/ec

pub fn sign_eab(
  mac_key: BitArray,
  kid kid: String,
  payload payload: String,
  url url: Url,
) -> Result(json.Json, String) {
  use key <- result.try(
    gose.from_octet_bits(mac_key)
    |> result.map_error(utils.gose_error_to_string),
  )

  let url = url.to_string(url)
  jws.new(gose.Mac(gose.Hmac(gose.HmacSha256)))
  |> jws.with_kid(kid)
  |> set_header("url", json.string(url))
  |> result.try(sign_and_serialize(_, key, payload))
}

pub fn sign_key_change_inner(
  new_key: jwk.Key,
  payload payload: String,
  url url: Url,
) -> Result(json.Json, String) {
  use alg <- result.try(algorithm_for_key(new_key))

  let url = url.to_string(url)
  jws.new(alg)
  |> set_header("url", json.string(url))
  |> result.try(with_jwk_identity(_, new_key))
  |> result.try(sign_and_serialize(_, new_key, payload))
}

pub fn sign_with_jwk(
  key: jwk.Key,
  payload payload: String,
  nonce nonce: String,
  url url: Url,
) -> Result(String, String) {
  sign_request(key, payload, nonce, url, with_jwk_identity(_, key))
}

pub fn sign_with_kid(
  key: jwk.Key,
  kid kid: Url,
  payload payload: String,
  nonce nonce: String,
  url url: Url,
) -> Result(String, String) {
  let kid_string = url.to_string(kid)
  sign_request(key, payload, nonce, url, fn(unsigned) {
    Ok(jws.with_kid(unsigned, kid_string))
  })
}

fn algorithm_for_ec_key(key: jwk.Key) -> Result(gose.SigningAlg, String) {
  use curve <- result.try(
    gose.ec_curve(key)
    |> result.replace_error("failed to get EC curve"),
  )

  case curve {
    ec.P256 -> Ok(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)))
    ec.P384 -> Ok(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP384)))
    ec.P521 -> Ok(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP521)))
    ec.Secp256k1 -> Error("Secp256k1 is not supported for ACME JWS signing")
  }
}

fn algorithm_for_key(key: jwk.Key) -> Result(gose.SigningAlg, String) {
  case gose.key_type(key) {
    gose.EcKeyType -> algorithm_for_ec_key(key)
    gose.RsaKeyType ->
      Ok(gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha256)))
    gose.OkpKeyType -> Ok(gose.DigitalSignature(gose.Eddsa))
    gose.OctKeyType -> Error("symmetric keys not supported for ACME")
  }
}

fn set_header(
  unsigned: jws.Jws(jws.Unsigned, jws.Built),
  name: String,
  value: json.Json,
) -> Result(jws.Jws(jws.Unsigned, jws.Built), String) {
  jws.with_header(unsigned, name, value)
  |> result.map_error(utils.gose_error_to_string)
}

fn sign_and_serialize(
  unsigned: jws.Jws(jws.Unsigned, jws.Built),
  key: jwk.Key,
  payload: String,
) -> Result(json.Json, String) {
  jws.sign(unsigned, key, bit_array.from_string(payload))
  |> result.map(jws.serialize_json_flattened)
  |> result.map_error(utils.gose_error_to_string)
}

fn sign_request(
  key: jwk.Key,
  payload: String,
  nonce: String,
  url: Url,
  with_identity: fn(jws.Jws(jws.Unsigned, jws.Built)) ->
    Result(jws.Jws(jws.Unsigned, jws.Built), String),
) -> Result(String, String) {
  use alg <- result.try(algorithm_for_key(key))

  let url = url.to_string(url)
  jws.new(alg)
  |> set_header("nonce", json.string(nonce))
  |> result.try(set_header(_, "url", json.string(url)))
  |> result.try(with_identity)
  |> result.try(sign_and_serialize(_, key, payload))
  |> result.map(json.to_string)
}

fn with_jwk_identity(
  unsigned: jws.Jws(jws.Unsigned, jws.Built),
  key: jwk.Key,
) -> Result(jws.Jws(jws.Unsigned, jws.Built), String) {
  use public_key <- result.try(
    gose.public_key(key) |> result.map_error(utils.gose_error_to_string),
  )
  set_header(unsigned, "jwk", jwk.to_json(public_key))
}
