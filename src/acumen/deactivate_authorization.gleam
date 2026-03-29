//// Deactivate an ACME authorization.
////
//// Relinquish authorization to issue certificates for an identifier. Use
//// this when you no longer want the server to consider you authorized.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/deactivate_authorization
////
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: deactivate_authorization.build(authz_url, _, registered_key),
////   send: httpc.send,
//// )
////
//// let assert Ok(authz) = deactivate_authorization.response(resp, authz_url)
//// // authz.status == Deactivated
//// ```

import acumen
import acumen/authorization.{type Authorization}
import acumen/internal/jws
import acumen/internal/utils
import acumen/url.{type Url}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/result

/// Builds a request to deactivate an ACME authorization.
pub fn build(
  url: Url,
  context: acumen.Context,
  key: acumen.RegisteredKey,
) -> Result(Request(String), acumen.AcmeError) {
  json.object([#("status", json.string("deactivated"))])
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

/// Parses the authorization deactivation response.
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
