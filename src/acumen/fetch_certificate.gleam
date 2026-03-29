//// Fetch an issued certificate from the ACME server.
////
//// After an order reaches the `Valid` status, use the certificate URL
//// from `order.Valid(certificate_url)` to download the certificate chain
//// in PEM format.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/fetch_certificate
//// import acumen/order
////
//// // After the order is valid...
//// let assert order.Valid(certificate_url) = completed_order.status
////
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: fetch_certificate.build(certificate_url, _, registered_key),
////   send: httpc.send,
//// )
////
//// let assert Ok(pem_chain) = fetch_certificate.response(resp)
//// ```

import acumen
import acumen/internal/utils
import acumen/url.{type Url}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/result

/// Builds a POST-as-GET request to fetch an issued certificate.
pub fn build(
  url: Url,
  context: acumen.Context,
  key: acumen.RegisteredKey,
) -> Result(Request(String), acumen.AcmeError) {
  acumen.build_fetch(url, context, key)
  |> result.map(request.set_header(
    _,
    "accept",
    "application/pem-certificate-chain",
  ))
}

/// Parses the certificate fetch response.
///
/// Returns the certificate chain in PEM format.
pub fn response(resp: Response(String)) -> Result(String, acumen.AcmeError) {
  case resp.status {
    200 -> Ok(resp.body)
    _ ->
      Error(
        acumen.InvalidResponse(utils.unexpected_status_message(resp.status)),
      )
  }
}
