//// Order types and CSR generation for ACME certificate requests.
////
//// An order represents a request for a certificate covering one or more
//// identifiers (domain names or IP addresses). This module also provides
//// helpers to generate Certificate Signing Requests (CSRs) from an order.

import acumen
import acumen/challenge
import acumen/internal/utils
import acumen/url.{type Url}
import gleam/dynamic/decode
import gleam/http/response.{type Response}
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import kryptos/ec
import kryptos/hash
import kryptos/rsa
import kryptos/x509
import kryptos/x509/csr

/// Errors that can occur when generating a CSR from an order.
pub type CsrError {
  /// The order has no identifiers.
  NoIdentifiers
  /// An identifier could not be encoded (e.g., non-ASCII DNS name, invalid IP).
  InvalidIdentifier
  /// The CSR could not be signed.
  SigningFailed
}

/// An ACME order for certificate issuance.
pub type Order {
  Order(
    /// The order URL (from Location header).
    url: Url,
    /// Current order status (certificate URL is inside `Valid` variant).
    status: Status,
    /// The identifiers requested on the certificate.
    identifiers: List(acumen.Identifier),
    /// URLs to authorization objects (for challenge completion).
    authorizations: List(Url),
    /// URL to finalize the order with a CSR.
    finalize_url: Url,
    /// When the order expires.
    expires: Option(Timestamp),
    /// Requested certificate notBefore (optional).
    not_before: Option(Timestamp),
    /// Requested certificate notAfter (optional).
    not_after: Option(Timestamp),
    /// Certificate issuance profile (optional).
    profile: Option(String),
    /// Problem document when order is invalid.
    error: Option(acumen.AcmeError),
  )
}

/// Order status.
pub type Status {
  /// Authorizations not yet satisfied.
  Pending
  /// Ready for finalization (all authorizations valid).
  Ready
  /// CA is issuing the certificate.
  Processing
  /// Certificate is available for download at the given URL.
  Valid(certificate_url: Url)
  /// Order failed (e.g., authorization failed).
  Invalid
}

/// Generates a CSR from an order using an EC key.
///
/// Uses the order's identifiers as Subject Alternative Names, with the first
/// DNS identifier as the Common Name. Returns the CSR in DER format.
///
/// ## Example
///
/// ```gleam
/// let #(private_key, _public_key) = ec.generate_key_pair(ec.P256)
/// let assert Ok(csr_der) = order.to_ec_csr(ready_order, private_key)
/// ```
pub fn to_ec_csr(
  order: Order,
  key: ec.PrivateKey,
) -> Result(BitArray, CsrError) {
  use builder <- result.try(build_csr_builder(order))
  let hash_algorithm = hash_for_ec_curve(ec.curve(key))
  csr.sign_with_ecdsa(builder, key, hash_algorithm)
  |> result.map(csr.to_der)
  |> result.replace_error(SigningFailed)
}

fn build_csr_builder(order: Order) -> Result(csr.Builder, CsrError) {
  case order.identifiers {
    [] -> Error(NoIdentifiers)
    identifiers -> {
      let subject = case list.find_map(identifiers, first_dns_name) {
        Ok(name) -> x509.name([x509.cn(name)])
        Error(_) -> x509.name([])
      }

      list.try_fold(identifiers, csr.new(), fn(builder, identifier) {
        case identifier {
          acumen.DnsIdentifier(name) -> csr.with_dns_name(builder, name)
          acumen.IpIdentifier(ip) -> csr.with_ip(builder, ip)
        }
      })
      |> result.map(csr.with_subject(_, subject))
      |> result.replace_error(InvalidIdentifier)
    }
  }
}

fn first_dns_name(identifier: acumen.Identifier) -> Result(String, Nil) {
  case identifier {
    acumen.DnsIdentifier(name) -> Ok(name)
    acumen.IpIdentifier(_) -> Error(Nil)
  }
}

fn hash_for_ec_curve(curve: ec.Curve) -> hash.HashAlgorithm {
  case curve {
    ec.P256 | ec.Secp256k1 -> hash.Sha256
    ec.P384 -> hash.Sha384
    ec.P521 -> hash.Sha512
  }
}

/// Generates a CSR from an order using an RSA key.
///
/// Uses the order's identifiers as Subject Alternative Names, with the first
/// DNS identifier as the Common Name. Returns the CSR in DER format.
///
/// Hash algorithm is selected by key size: SHA-512 for 4096+ bits,
/// SHA-384 for 3072+, SHA-256 otherwise.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(#(private_key, _public_key)) = rsa.generate_key_pair(2048)
/// let assert Ok(csr_der) = order.to_rsa_csr(ready_order, private_key)
/// ```
pub fn to_rsa_csr(
  order: Order,
  key: rsa.PrivateKey,
) -> Result(BitArray, CsrError) {
  use builder <- result.try(build_csr_builder(order))
  let hash_algorithm = hash_for_rsa_key(key)
  csr.sign_with_rsa(builder, key, hash_algorithm)
  |> result.map(csr.to_der)
  |> result.replace_error(SigningFailed)
}

fn hash_for_rsa_key(key: rsa.PrivateKey) -> hash.HashAlgorithm {
  case rsa.modulus_bits(key) {
    bits if bits >= 4096 -> hash.Sha512
    bits if bits >= 3072 -> hash.Sha384
    _ -> hash.Sha256
  }
}

@internal
pub fn decoder(url: Url) -> decode.Decoder(Order) {
  use status <- decode.then(status_decoder())
  use identifiers <- decode.field(
    "identifiers",
    decode.list(acumen.identifier_decoder()),
  )
  use authorizations <- decode.field(
    "authorizations",
    decode.list(url.decoder()),
  )
  use finalize_url <- decode.field("finalize", url.decoder())
  use expires <- decode.optional_field(
    "expires",
    option.None,
    decode.optional(utils.timestamp_decoder()),
  )
  use not_before <- decode.optional_field(
    "notBefore",
    option.None,
    decode.optional(utils.timestamp_decoder()),
  )
  use not_after <- decode.optional_field(
    "notAfter",
    option.None,
    decode.optional(utils.timestamp_decoder()),
  )
  use profile <- decode.optional_field(
    "profile",
    option.None,
    decode.optional(decode.string),
  )
  use error <- decode.optional_field(
    "error",
    option.None,
    challenge.error_decoder(),
  )
  decode.success(Order(
    url:,
    status:,
    identifiers:,
    authorizations:,
    finalize_url:,
    expires:,
    not_before:,
    not_after:,
    profile:,
    error:,
  ))
}

fn status_decoder() -> decode.Decoder(Status) {
  use status_string <- decode.field("status", decode.string)
  use certificate_url <- decode.optional_field(
    "certificate",
    option.None,
    decode.optional(url.decoder()),
  )
  case status_string, certificate_url {
    "pending", _ -> decode.success(Pending)
    "ready", _ -> decode.success(Ready)
    "processing", _ -> decode.success(Processing)
    "valid", option.Some(url) -> decode.success(Valid(url))
    "valid", option.None ->
      decode.failure(Pending, "OrderStatus(valid requires certificate URL)")
    "invalid", _ -> decode.success(Invalid)
    _, _ ->
      decode.failure(Pending, "OrderStatus(unknown: " <> status_string <> ")")
  }
}

@internal
pub fn parse_order_response(
  resp: Response(String),
  order_url: Url,
) -> Result(Order, acumen.AcmeError) {
  json.parse(resp.body, decoder(order_url))
  |> result.map_error(fn(error) {
    acumen.JsonParseError(utils.json_parse_error_message("order", error:))
  })
}
