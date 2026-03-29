//// Revoke certificates issued through ACME.
////
//// Once revoked, a certificate appears on Certificate Revocation Lists (CRLs).
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/revoke_certificate
////
//// // Build the revocation request with the DER-encoded certificate
//// let rev = revoke_certificate.request(cert_der_bytes)
////   |> revoke_certificate.reason(revoke_certificate.KeyCompromise)
////
//// // Execute the request
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: revoke_certificate.build(rev, _, registered_key),
////   send: httpc.send,
//// )
////
//// // Parse the response
//// let assert Ok(Nil) = revoke_certificate.response(resp)
//// ```

import acumen
import acumen/internal/jws
import acumen/internal/utils
import gleam/bit_array
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/option.{type Option}
import gleam/result
import gose/jwk.{type Jwk}

/// Request builder for certificate revocation.
///
/// Use `request` to create a builder with the DER-encoded certificate,
/// optionally configure it with `reason`, then call `build`.
pub opaque type RequestBuilder {
  RequestBuilder(certificate: BitArray, reason: Option(RevocationReason))
}

/// Reason codes for certificate revocation as defined in RFC 5280.
///
/// Not all reason codes are commonly used. The most common are:
/// - `Unspecified`: No specific reason given
/// - `KeyCompromise`: The certificate's private key was compromised
/// - `Superseded`: The certificate has been replaced by a newer one
/// - `CessationOfOperation`: The certificate is no longer needed
pub type RevocationReason {
  /// No specific reason given (code 0)
  Unspecified
  /// The certificate's private key was compromised (code 1)
  KeyCompromise
  /// The CA's private key was compromised (code 2)
  CaCompromise
  /// The certificate holder's affiliation changed (code 3)
  AffiliationChanged
  /// The certificate has been replaced (code 4)
  Superseded
  /// The certificate is no longer needed (code 5)
  CessationOfOperation
  /// The certificate is temporarily on hold (code 6)
  CertificateHold
  /// Remove the certificate from a CRL (code 8)
  RemoveFromCrl
  /// Privileges were withdrawn (code 9)
  PrivilegeWithdrawn
  /// The attribute authority was compromised (code 10)
  AaCompromise
}

/// Builds a signed revocation request to the `revokeCert` endpoint.
pub fn build(
  builder: RequestBuilder,
  context: acumen.Context,
  key: acumen.RegisteredKey,
) -> Result(Request(String), acumen.AcmeError) {
  build_payload(builder)
  |> json.to_string
  |> jws.sign_with_kid(
    key.jwk,
    kid: key.kid,
    payload: _,
    nonce: context.nonce,
    url: context.directory.revoke_cert,
  )
  |> result.map_error(acumen.JwsError)
  |> result.try(acumen.build_post_request(context.directory.revoke_cert, _))
}

fn build_payload(builder: RequestBuilder) -> json.Json {
  let encoded = bit_array.base64_url_encode(builder.certificate, False)
  let fields = [#("certificate", json.string(encoded))]

  let fields = case builder.reason {
    option.Some(revocation_reason) -> [
      #("reason", json.int(reason_to_code(revocation_reason))),
      ..fields
    ]
    option.None -> fields
  }

  json.object(fields)
}

fn reason_to_code(revocation_reason: RevocationReason) -> Int {
  case revocation_reason {
    Unspecified -> 0
    KeyCompromise -> 1
    CaCompromise -> 2
    AffiliationChanged -> 3
    Superseded -> 4
    CessationOfOperation -> 5
    CertificateHold -> 6
    RemoveFromCrl -> 8
    PrivilegeWithdrawn -> 9
    AaCompromise -> 10
  }
}

/// Signs the revocation request with the certificate's private key instead
/// of the account key. Useful when account access is unavailable, such as
/// during incident response.
///
/// ## Example
///
/// ```gleam
/// import acumen
/// import acumen/revoke_certificate
/// import gose/jwk
///
/// let assert Ok(cert_private_key) = jwk.from_pem(cert_key_pem)
///
/// let req = revoke_certificate.request(cert_der_bytes)
///   |> revoke_certificate.reason(revoke_certificate.KeyCompromise)
///
/// let assert Ok(#(resp, ctx)) = acumen.execute(
///   ctx,
///   build: revoke_certificate.build_with_certificate_key(
///     req,
///     _,
///     key: cert_private_key,
///   ),
///   send: httpc.send,
/// )
///
/// let assert Ok(Nil) = revoke_certificate.response(resp)
/// ```
pub fn build_with_certificate_key(
  builder: RequestBuilder,
  context: acumen.Context,
  key key: Jwk,
) -> Result(Request(String), acumen.AcmeError) {
  build_payload(builder)
  |> json.to_string
  |> jws.sign_with_jwk(
    key,
    payload: _,
    nonce: context.nonce,
    url: context.directory.revoke_cert,
  )
  |> result.map_error(acumen.JwsError)
  |> result.try(acumen.build_post_request(context.directory.revoke_cert, _))
}

/// Sets the revocation reason. Optional but recommended.
pub fn reason(
  builder: RequestBuilder,
  revocation_reason: RevocationReason,
) -> RequestBuilder {
  RequestBuilder(..builder, reason: option.Some(revocation_reason))
}

/// Creates a new revocation request builder with the given DER-encoded certificate.
pub fn request(certificate_der: BitArray) -> RequestBuilder {
  RequestBuilder(certificate: certificate_der, reason: option.None)
}

/// Parses the revocation response. Empty body on success.
pub fn response(resp: Response(String)) -> Result(Nil, acumen.AcmeError) {
  case resp.status {
    200 -> Ok(Nil)
    _ ->
      Error(
        acumen.InvalidResponse(utils.unexpected_status_message(resp.status)),
      )
  }
}
