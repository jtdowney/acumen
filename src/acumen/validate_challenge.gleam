//// Trigger validation of an ACME challenge.
////
//// After setting up the challenge response (HTTP file, DNS record, etc.),
//// use this to tell the ACME server to validate it.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/challenge
//// import acumen/validate_challenge
////
//// // After deploying the challenge response...
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: validate_challenge.build(challenge.url(http_challenge), _, registered_key),
////   send: httpc.send,
//// )
////
//// let assert Ok(updated_challenge) = validate_challenge.response(resp)
//// ```

import acumen
import acumen/challenge.{type Challenge}
import acumen/internal/jws
import acumen/internal/utils
import acumen/url.{type Url}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/result

/// Builds the POST request to trigger challenge validation.
pub fn build(
  url: Url,
  context: acumen.Context,
  key: acumen.RegisteredKey,
) -> Result(Request(String), acumen.AcmeError) {
  json.object([])
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

/// Parses the challenge response after triggering validation.
///
/// The returned challenge status may still be `Processing`.
pub fn response(resp: Response(String)) -> Result(Challenge, acumen.AcmeError) {
  case resp.status {
    200 -> parse_challenge_response(resp)
    _ ->
      Error(
        acumen.InvalidResponse(utils.unexpected_status_message(resp.status)),
      )
  }
}

fn parse_challenge_response(
  resp: Response(String),
) -> Result(Challenge, acumen.AcmeError) {
  json.parse(resp.body, challenge.decoder())
  |> result.map_error(fn(error) {
    acumen.JsonParseError(utils.json_parse_error_message("challenge", error:))
  })
}
