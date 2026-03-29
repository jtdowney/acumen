//// Finalize an ACME order with a Certificate Signing Request.
////
//// After all authorizations are valid (order status is `Ready`), submit a CSR
//// to finalize the order and trigger certificate issuance.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/finalize_order
//// import acumen/order
////
//// // Generate a CSR from the order
//// let assert Ok(csr) = order.to_ec_csr(ready_order, cert_key)
////
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: finalize_order.build(ready_order.finalize_url, _, registered_key, csr:),
////   send: httpc.send,
//// )
////
//// let assert Ok(finalized) = finalize_order.response(resp, ready_order.url)
//// ```

import acumen
import acumen/internal/jws
import acumen/internal/utils
import acumen/order.{type Order}
import acumen/url.{type Url}
import gleam/bit_array
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/result

/// Builds the HTTP request to finalize an order with a CSR.
///
/// The `csr` must be in DER format; the library handles base64url encoding.
pub fn build(
  url: Url,
  context: acumen.Context,
  key: acumen.RegisteredKey,
  csr csr: BitArray,
) -> Result(Request(String), acumen.AcmeError) {
  let csr_encoded =
    csr
    |> bit_array.base64_url_encode(False)
    |> json.string

  json.object([#("csr", csr_encoded)])
  |> json.to_string
  |> jws.sign_with_kid(
    key.jwk,
    kid: key.kid,
    payload: _,
    nonce: context.nonce,
    url:,
  )
  |> result.map_error(acumen.JwsError)
  |> result.try(acumen.build_post_request(url, _))
}

/// Parses the finalize response.
///
/// Returns the order, typically in `Processing` or `Valid` status.
/// Pass the `order_url` directly since the finalize response does not
/// include a Location header.
pub fn response(
  resp: Response(String),
  order_url order_url: Url,
) -> Result(Order, acumen.AcmeError) {
  case resp.status {
    200 -> order.parse_order_response(resp, order_url)
    _ ->
      Error(
        acumen.InvalidResponse(utils.unexpected_status_message(resp.status)),
      )
  }
}
