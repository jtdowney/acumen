//// Fetch an ACME authorization.
////
//// After creating an order, fetch each authorization to see the available
//// challenges for proving domain control.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/authorization.{type Authorization}
//// import acumen/fetch_authorization
////
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: fetch_authorization.build(auth_url, _, registered_key),
////   send: httpc.send,
//// )
////
//// let assert Ok(auth) = fetch_authorization.response(resp, auth_url)
//// ```

import acumen
import acumen/authorization.{type Authorization}
import acumen/internal/utils
import acumen/url.{type Url}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}

/// Builds a signed POST-as-GET request to fetch an authorization.
pub fn build(
  url: Url,
  context: acumen.Context,
  key: acumen.RegisteredKey,
) -> Result(Request(String), acumen.AcmeError) {
  acumen.build_fetch(url, context, key)
}

/// Parses an authorization fetch response.
pub fn response(
  resp: Response(String),
  url url: Url,
) -> Result(Authorization, acumen.AcmeError) {
  case resp.status {
    200 -> authorization.parse_authorization_response(resp, url)
    _ ->
      Error(
        acumen.InvalidResponse(utils.unexpected_status_message(resp.status)),
      )
  }
}
