//// List orders associated with an ACME account.
////
//// The ACME server provides a paginated list of order URLs for each account.
//// Use the `next` field in the response to fetch subsequent pages.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/list_orders.{type OrdersList}
//// import gleam/option
////
//// let assert option.Some(orders_url) = account.orders_url
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: list_orders.build(orders_url, _, registered_key),
////   send: httpc.send,
//// )
////
//// let assert Ok(orders_list) = list_orders.response(resp)
//// ```

import acumen
import acumen/internal/link_header
import acumen/internal/utils
import acumen/url.{type Url}
import gleam/dynamic/decode
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/result

/// A paginated list of order URLs from the ACME server.
pub type OrdersList {
  OrdersList(
    /// The order URLs on this page.
    orders: List(Url),
    /// URL to fetch the next page, if one exists.
    next: Option(Url),
  )
}

/// Builds a signed POST-as-GET request to list orders for an account.
///
/// Targets the account's `orders` URL from the registration response.
pub fn build(
  url: Url,
  context: acumen.Context,
  key: acumen.RegisteredKey,
) -> Result(Request(String), acumen.AcmeError) {
  acumen.build_fetch(url, context, key)
}

/// Parses the orders list response.
///
/// Pagination is indicated by a `Link` header with `rel="next"`.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(orders_list) = list_orders.response(resp)
///
/// // Follow pagination if there are more pages
/// case orders_list.next {
///   option.Some(next_url) -> {
///     let assert Ok(#(resp, ctx)) = acumen.execute(
///       ctx,
///       build: list_orders.build(next_url, _, registered_key),
///       send: httpc.send,
///     )
///     let assert Ok(next_page) = list_orders.response(resp)
///   }
///   option.None -> {
///     // No more pages
///   }
/// }
/// ```
pub fn response(resp: Response(String)) -> Result(OrdersList, acumen.AcmeError) {
  case resp.status {
    200 -> parse_orders_response(resp)
    _ ->
      Error(
        acumen.InvalidResponse(utils.unexpected_status_message(resp.status)),
      )
  }
}

fn parse_orders_response(
  resp: Response(String),
) -> Result(OrdersList, acumen.AcmeError) {
  let decoder =
    decode.field("orders", decode.list(url.decoder()), decode.success)

  json.parse(resp.body, decoder)
  |> result.map_error(fn(error) {
    acumen.JsonParseError(utils.json_parse_error_message("orders list", error:))
  })
  |> result.map(fn(orders) {
    let next = parse_next_link(resp) |> option.from_result
    OrdersList(orders:, next:)
  })
}

fn parse_next_link(resp: Response(String)) -> Result(Url, Nil) {
  resp.headers
  |> list.key_filter("link")
  |> list.find_map(link_header.find_by_rel(_, rel: "next"))
}
