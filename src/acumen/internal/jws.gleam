import acumen/internal/utils
import acumen/url.{type Url}
import gleam/bit_array
import gleam/json
import gleam/result
import gose/jwa
import gose/jwk.{type Jwk}
import gose/jws
import kryptos/ec

pub fn sign_eab(
  mac_key: BitArray,
  kid kid: String,
  payload payload: String,
  url url: Url,
) -> Result(json.Json, String) {
  use key <- result.try(
    jwk.from_octet_bits(mac_key)
    |> result.map_error(utils.gose_error_to_string),
  )

  let url = url.to_string(url)
  jws.new(jwa.JwsHmac(jwa.HmacSha256))
  |> jws.with_kid(kid)
  |> set_header("url", json.string(url))
  |> result.try(sign_and_serialize(_, key, payload))
}

pub fn sign_key_change_inner(
  new_key: Jwk,
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
  key: Jwk,
  payload payload: String,
  nonce nonce: String,
  url url: Url,
) -> Result(String, String) {
  sign_request(key, payload, nonce, url, with_jwk_identity(_, key))
}

pub fn sign_with_kid(
  key: Jwk,
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

fn algorithm_for_ec_key(key: Jwk) -> Result(jwa.JwsAlg, String) {
  use curve <- result.try(
    jwk.ec_curve(key)
    |> result.replace_error("failed to get EC curve"),
  )

  case curve {
    ec.P256 -> Ok(jwa.JwsEcdsa(jwa.EcdsaP256))
    ec.P384 -> Ok(jwa.JwsEcdsa(jwa.EcdsaP384))
    ec.P521 -> Ok(jwa.JwsEcdsa(jwa.EcdsaP521))
    ec.Secp256k1 -> Error("Secp256k1 is not supported for ACME JWS signing")
  }
}

fn algorithm_for_key(key: Jwk) -> Result(jwa.JwsAlg, String) {
  case jwk.key_type(key) {
    jwk.EcKeyType -> algorithm_for_ec_key(key)
    jwk.RsaKeyType -> Ok(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256))
    jwk.OkpKeyType -> Ok(jwa.JwsEddsa)
    jwk.OctKeyType -> Error("symmetric keys not supported for ACME")
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
  key: Jwk,
  payload: String,
) -> Result(json.Json, String) {
  jws.sign(unsigned, key, bit_array.from_string(payload))
  |> result.map(jws.serialize_json_flattened)
  |> result.map_error(utils.gose_error_to_string)
}

fn sign_request(
  key: Jwk,
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
  key: Jwk,
) -> Result(jws.Jws(jws.Unsigned, jws.Built), String) {
  use public_key <- result.try(
    jwk.public_key(key) |> result.map_error(utils.gose_error_to_string),
  )
  set_header(unsigned, "jwk", jwk.to_json(public_key))
}
