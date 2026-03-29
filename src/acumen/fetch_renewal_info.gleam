//// Fetch renewal information for a certificate (RFC 9773).
////
//// Queries the ACME server for a suggested renewal window for a specific
//// certificate. This uses an unauthenticated GET request (no JWS signing
//// needed), so it does not require `acumen.execute` — just build, send,
//// and parse the response directly.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/fetch_renewal_info
//// import acumen/renewal_info
//// import gleam/httpc
//// import kryptos/x509/certificate
////
//// // Parse the certificate and build the identifier
//// let assert Ok(certs) = certificate.from_pem(pem)
//// let assert [cert, ..] = certs
//// let assert Ok(cert_id) = renewal_info.cert_id_from_certificate(cert)
////
//// // Fetch renewal information
//// let assert Ok(req) = fetch_renewal_info.build(directory, cert_id)
//// let assert Ok(resp) = httpc.send(req)
//// let assert Ok(info) = fetch_renewal_info.response(resp)
////
//// // Check the suggested renewal window
//// let start = info.suggested_window.start
//// let end = info.suggested_window.end
////
//// // Check polling interval
//// let retry = acumen.retry_after(resp)
//// ```

import acumen
import acumen/internal/constants
import acumen/internal/utils
import acumen/renewal_info.{type RenewalInfo}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/option
import gleam/result
import gleam/string
import gleam/uri

/// Builds an HTTP GET request to fetch renewal information for a certificate.
///
/// Targets `{renewalInfo_url}/{cert_id}`. Build the `cert_id` with
/// `renewal_info.cert_id` or `renewal_info.cert_id_from_certificate`.
pub fn build(
  directory: acumen.Directory,
  cert_id cert_id: String,
) -> Result(Request(String), acumen.AcmeError) {
  case directory.renewal_info {
    option.None ->
      Error(acumen.InvalidRequest(
        "directory does not include renewalInfo endpoint",
      ))
    option.Some(base_uri) -> {
      let base_path = case string.ends_with(base_uri.path, "/") {
        True -> base_uri.path
        False -> base_uri.path <> "/"
      }

      uri.Uri(..base_uri, path: base_path <> cert_id)
      |> request.from_uri
      |> result.map(fn(req) {
        req
        |> request.set_header("user-agent", "acumen/" <> constants.version)
        |> request.set_header("accept-language", "en")
      })
      |> result.replace_error(acumen.InvalidRequest("invalid renewalInfo URI"))
    }
  }
}

/// Parses a renewal information response.
pub fn response(resp: Response(String)) -> Result(RenewalInfo, acumen.AcmeError) {
  case resp.status {
    200 ->
      json.parse(resp.body, renewal_info.decoder())
      |> result.map_error(fn(error) {
        acumen.JsonParseError(utils.json_parse_error_message(
          "renewalInfo",
          error:,
        ))
      })
    _ -> Error(acumen.parse_acme_error(resp))
  }
}
