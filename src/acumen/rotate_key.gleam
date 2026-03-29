//// Account key rotation for ACME.
////
//// Key rotation allows you to replace your account's key pair while maintaining
//// account continuity.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/rotate_key
//// import gose/jwk
//// import kryptos/ec
////
//// // Generate a new key to rotate to
//// let new_key = jwk.generate_ec(ec.P256)
////
//// // Build and execute the key change request
//// let change = rotate_key.request(new_key)
////
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: rotate_key.build(change, _, old_registered_key),
////   send: httpc.send,
//// )
////
//// // Parse the response to get the new registered key
//// let assert Ok(new_registered_key) =
////   rotate_key.response(resp, new_key, old_registered_key)
//// ```

import acumen
import acumen/internal/jws
import acumen/internal/utils
import acumen/url.{type Url}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/result
import gose/jwk.{type Jwk}

/// Request builder for key rotation.
///
/// Use `request` to create a builder with the new key, then call `build`.
pub opaque type RequestBuilder {
  RequestBuilder(new_key: Jwk)
}

/// Builds the HTTP request for key rotation.
///
/// Creates a nested JWS: inner payload `{account, oldKey}` signed with the
/// new key, wrapped in an outer JWS signed with the old key.
pub fn build(
  builder: RequestBuilder,
  context: acumen.Context,
  key: acumen.RegisteredKey,
) -> Result(Request(String), acumen.AcmeError) {
  build_inner(builder.new_key, key, context.directory.key_change)
  |> result.map(json.to_string)
  |> result.try(jws.sign_with_kid(
    key.jwk,
    kid: key.kid,
    payload: _,
    nonce: context.nonce,
    url: context.directory.key_change,
  ))
  |> result.map_error(acumen.JwsError)
  |> result.try(acumen.build_post_request(context.directory.key_change, _))
}

fn build_inner(
  new_key: Jwk,
  old_key: acumen.RegisteredKey,
  url: Url,
) -> Result(json.Json, String) {
  use old_public_key <- result.try(
    jwk.public_key(old_key.jwk)
    |> result.map_error(utils.gose_error_to_string),
  )

  json.object([
    #("account", json.string(url.to_string(old_key.kid))),
    #("oldKey", jwk.to_json(old_public_key)),
  ])
  |> json.to_string
  |> jws.sign_key_change_inner(new_key, payload: _, url:)
}

/// Creates a new key rotation request builder wrapping the replacement key.
pub fn request(new_key: Jwk) -> RequestBuilder {
  RequestBuilder(new_key: new_key)
}

/// Parses the key rotation response.
///
/// Returns a new `RegisteredKey` with the new key and the old key's
/// account URL.
pub fn response(
  resp: Response(String),
  new_key new_key: Jwk,
  old_key old_key: acumen.RegisteredKey,
) -> Result(acumen.RegisteredKey, acumen.AcmeError) {
  case resp.status {
    200 -> Ok(acumen.RegisteredKey(jwk: new_key, kid: old_key.kid))
    _ ->
      Error(
        acumen.InvalidResponse(utils.unexpected_status_message(resp.status)),
      )
  }
}
