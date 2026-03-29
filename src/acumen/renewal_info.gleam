//// Renewal information types and certificate identifier helpers (RFC 9773).
////
//// The ACME Renewal Information (ARI) extension allows servers to suggest
//// optimal renewal windows for certificates.
////
//// ## Example
////
//// ```gleam
//// import acumen/renewal_info
//// import kryptos/x509/certificate
////
//// // From raw components:
//// let id = renewal_info.cert_id(aki_bytes, serial_bytes)
////
//// // From a parsed certificate:
//// let assert Ok(certs) = certificate.from_pem(pem_string)
//// let assert [cert, ..] = certs
//// let assert Ok(id) = renewal_info.cert_id_from_certificate(cert)
//// ```

import acumen
import acumen/internal/utils
import gleam/bit_array
import gleam/dynamic/decode
import gleam/option.{type Option}
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import gleam/uri.{type Uri}
import kryptos/x509/certificate.{type Certificate}

/// Renewal information from an ACME server (RFC 9773).
pub type RenewalInfo {
  RenewalInfo(
    /// The server's suggested renewal window.
    suggested_window: SuggestedWindow,
    /// URL with additional context about the renewal recommendation.
    explanation_url: Option(Uri),
  )
}

/// A suggested renewal window with start and end timestamps.
pub type SuggestedWindow {
  SuggestedWindow(start: Timestamp, end: Timestamp)
}

/// Builds a certificate identifier from raw AKI keyIdentifier and serial number bytes.
///
/// The identifier format is `base64url(AKI) "." base64url(serial)` as specified
/// by RFC 9773. This identifier is used both for querying renewal information
/// and for the `replaces` field in order creation.
///
/// ## Example
///
/// ```gleam
/// let id = renewal_info.cert_id(aki_bytes, serial_bytes)
/// ```
pub fn cert_id(
  authority_key_identifier authority_key_identifier: BitArray,
  serial serial: BitArray,
) -> String {
  bit_array.base64_url_encode(authority_key_identifier, False)
  <> "."
  <> bit_array.base64_url_encode(serial, False)
}

/// Extracts a certificate identifier from a parsed certificate.
///
/// Extracts the Authority Key Identifier (AKI) keyIdentifier and serial
/// number, and constructs the RFC 9773 certificate identifier.
///
/// Parse certificates with `kryptos/x509/certificate.from_pem` or
/// `kryptos/x509/certificate.from_der` before calling this function.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(certs) = certificate.from_pem(pem_string)
/// let assert [cert, ..] = certs
/// let assert Ok(id) = renewal_info.cert_id_from_certificate(cert)
/// ```
pub fn cert_id_from_certificate(
  cert: Certificate(certificate.Parsed),
) -> Result(String, acumen.AcmeError) {
  use aki <- result.try(
    certificate.authority_key_identifier(cert)
    |> result.replace_error(acumen.InvalidRequest(
      "certificate missing Authority Key Identifier extension",
    )),
  )

  case aki.key_identifier {
    option.Some(key_id) -> Ok(cert_id(key_id, certificate.serial_number(cert)))
    option.None ->
      Error(acumen.InvalidRequest("AKI missing keyIdentifier field"))
  }
}

@internal
pub fn decoder() -> decode.Decoder(RenewalInfo) {
  let suggested_window_decoder = {
    use start <- decode.field("start", utils.timestamp_decoder())
    use end <- decode.field("end", utils.timestamp_decoder())
    decode.success(SuggestedWindow(start:, end:))
  }

  use suggested_window <- decode.field(
    "suggestedWindow",
    suggested_window_decoder,
  )
  use explanation_url <- decode.optional_field(
    "explanationURL",
    option.None,
    decode.optional(utils.uri_decoder()),
  )
  decode.success(RenewalInfo(suggested_window:, explanation_url:))
}
