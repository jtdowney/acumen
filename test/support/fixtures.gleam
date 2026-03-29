import acumen
import acumen/order.{type Order}
import acumen/url
import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/http/response.{type Response}
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/uri
import gose/jwk.{type Jwk}
import kryptos/ec
import kryptos/rsa
import simplifile

fn rsa_2048_pem() -> String {
  let assert Ok(pem) = simplifile.read("test/support/rsa_2048.pem")
  pem
}

pub fn test_rsa_jwk() -> Jwk {
  let assert Ok(key) = jwk.from_pem(rsa_2048_pem())
  key
}

pub fn test_rsa_key_pair() -> #(rsa.PrivateKey, rsa.PublicKey) {
  let assert Ok(pair) = rsa.from_pem(rsa_2048_pem(), rsa.Pkcs8)
  pair
}

pub fn test_ec_key() -> Jwk {
  jwk.generate_ec(ec.P256)
}

pub fn test_registered_key() -> acumen.RegisteredKey {
  let assert Ok(kid) = url.from_string("https://example.com/acct/123")
  acumen.RegisteredKey(jwk: test_ec_key(), kid: kid)
}

pub fn test_unregistered_key() -> acumen.UnregisteredKey {
  acumen.UnregisteredKey(test_ec_key())
}

pub fn test_directory() -> acumen.Directory {
  let assert Ok(endpoint) = url.from_string("https://example.com/endpoint")
  acumen.Directory(
    new_nonce: endpoint,
    new_account: endpoint,
    new_order: endpoint,
    revoke_cert: endpoint,
    key_change: endpoint,
    new_authz: option.None,
    renewal_info: option.None,
    meta: option.None,
  )
}

pub fn test_directory_with_meta(
  terms_of_service terms_of_service: Option(uri.Uri),
  external_account_required external_account_required: Bool,
) -> acumen.Directory {
  acumen.Directory(
    ..test_directory(),
    meta: option.Some(acumen.DirectoryMeta(
      terms_of_service: terms_of_service,
      website: option.None,
      caa_identities: [],
      external_account_required: external_account_required,
      profiles: dict.new(),
    )),
  )
}

pub fn test_directory_with_profiles(
  profiles: Dict(String, String),
) -> acumen.Directory {
  acumen.Directory(
    ..test_directory(),
    meta: option.Some(acumen.DirectoryMeta(
      terms_of_service: option.None,
      website: option.None,
      caa_identities: [],
      external_account_required: False,
      profiles:,
    )),
  )
}

pub fn test_context() -> acumen.Context {
  acumen.Context(directory: test_directory(), nonce: "test-nonce")
}

pub fn acme_response(
  status: Int,
  nonce: String,
  location: String,
  body: String,
) -> Response(String) {
  response.new(status)
  |> response.set_header("replay-nonce", nonce)
  |> response.set_header("location", location)
  |> response.set_body(body)
}

pub fn nonce_response(
  status: Int,
  nonce: String,
  body: String,
) -> Response(String) {
  response.new(status)
  |> response.set_header("replay-nonce", nonce)
  |> response.set_body(body)
}

pub fn identifier_json(identifier: acumen.Identifier) -> json.Json {
  let #(type_name, value) = case identifier {
    acumen.DnsIdentifier(value) -> #("dns", value)
    acumen.IpIdentifier(value) -> #("ip", value)
  }
  json.object([
    #("type", json.string(type_name)),
    #("value", json.string(value)),
  ])
}

pub fn identifiers_json(identifiers: List(acumen.Identifier)) -> json.Json {
  json.array(identifiers, identifier_json)
}

pub fn minimal_order_fields(domains: List(String)) -> List(#(String, json.Json)) {
  minimal_order_fields_with_status(domains, "pending")
}

pub fn minimal_order_fields_with_status(
  domains: List(String),
  status: String,
) -> List(#(String, json.Json)) {
  let identifiers =
    domains
    |> list.map(acumen.DnsIdentifier)
    |> identifiers_json
  [
    #("status", json.string(status)),
    #("identifiers", identifiers),
    #(
      "authorizations",
      json.array(["https://example.com/authz/1"], json.string),
    ),
    #("finalize", json.string("https://example.com/finalize/1")),
  ]
}

pub fn test_order(identifiers: List(acumen.Identifier)) -> Order {
  let assert Ok(order_url) = url.from_string("https://example.com/order/123")
  let assert Ok(finalize_url) =
    url.from_string("https://example.com/finalize/123")
  let assert Ok(authz_url) = url.from_string("https://example.com/authz/1")

  order.Order(
    url: order_url,
    status: order.Ready,
    identifiers: identifiers,
    authorizations: [authz_url],
    finalize_url: finalize_url,
    expires: option.None,
    not_before: option.None,
    not_after: option.None,
    profile: option.None,
    error: option.None,
  )
}

pub fn extract_jws_payload(jws_json: String) -> Result(String, Nil) {
  extract_jws_field(jws_json, "payload")
}

pub fn extract_protected_header(jws_json: String) -> Result(String, Nil) {
  extract_jws_field(jws_json, "protected")
}

fn extract_jws_field(jws_json: String, field: String) -> Result(String, Nil) {
  use field_b64 <- result.try(
    json.parse(jws_json, decode.at([field], decode.string))
    |> result.replace_error(Nil),
  )
  use decoded <- result.try(bit_array.base64_url_decode(field_b64))
  bit_array.to_string(decoded)
}
