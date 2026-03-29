//// Fetch an existing ACME order.
////
//// Use this to check the status of an order after creating it or to poll
//// for status changes during certificate issuance.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/fetch_order
//// import acumen/order.{type Order}
////
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: fetch_order.build(existing_order.url, _, registered_key),
////   send: httpc.send,
//// )
////
//// let assert Ok(updated_order) = fetch_order.response(resp, existing_order.url)
//// ```

import acumen
import acumen/internal/utils
import acumen/order.{type Order}
import acumen/url.{type Url}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}

/// Builds a signed POST-as-GET request to fetch an existing order.
///
/// Used to poll order status during the authorization and finalization flow.
pub fn build(
  url: Url,
  context: acumen.Context,
  key: acumen.RegisteredKey,
) -> Result(Request(String), acumen.AcmeError) {
  acumen.build_fetch(url, context, key)
}

/// Parses the order fetch response.
///
/// Pass the order URL since the response doesn't include a Location header.
pub fn response(
  resp: Response(String),
  url url: Url,
) -> Result(Order, acumen.AcmeError) {
  case resp.status {
    200 -> order.parse_order_response(resp, url)
    _ ->
      Error(
        acumen.InvalidResponse(utils.unexpected_status_message(resp.status)),
      )
  }
}
