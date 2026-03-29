//// Authorization types for ACME domain validation.
////
//// An authorization represents the server's authorization for an account
//// to represent a specific identifier (domain). Each authorization contains
//// one or more challenges that can be completed to prove control.

import acumen
import acumen/challenge.{type Challenge}
import acumen/internal/utils
import acumen/url.{type Url}
import gleam/dynamic/decode
import gleam/http/response.{type Response}
import gleam/json
import gleam/option.{type Option}
import gleam/result
import gleam/time/timestamp.{type Timestamp}

/// An ACME authorization for an identifier.
pub type Authorization {
  Authorization(
    /// The authorization URL.
    url: Url,
    /// Current authorization status.
    status: Status,
    /// The identifier (domain or IP) being authorized.
    identifier: acumen.Identifier,
    /// Available challenges to complete.
    challenges: List(Challenge),
    /// When the authorization expires.
    expires: Option(Timestamp),
    /// Whether this is for a wildcard domain.
    wildcard: Bool,
  )
}

/// Authorization status.
pub type Status {
  /// Authorization created, challenges not yet completed.
  Pending
  /// A challenge was successfully completed.
  Valid
  /// A challenge failed or authorization was abandoned.
  Invalid
  /// Authorization was deactivated by the client.
  Deactivated
  /// Authorization expired before completion.
  Expired
  /// Authorization was revoked by the server.
  Revoked
}

@internal
pub fn decoder(url: Url) -> decode.Decoder(Authorization) {
  use status <- decode.field("status", status_decoder())
  use identifier <- decode.field("identifier", acumen.identifier_decoder())
  use challenges <- decode.field(
    "challenges",
    decode.list(challenge.optional_decoder()) |> decode.map(option.values),
  )
  use expires <- decode.optional_field(
    "expires",
    option.None,
    decode.optional(utils.timestamp_decoder()),
  )
  use wildcard <- decode.optional_field("wildcard", False, decode.bool)
  decode.success(Authorization(
    url:,
    status:,
    identifier:,
    challenges:,
    expires:,
    wildcard:,
  ))
}

@internal
pub fn parse_authorization_response(
  resp: Response(String),
  authorization_url: Url,
) -> Result(Authorization, acumen.AcmeError) {
  json.parse(resp.body, decoder(authorization_url))
  |> result.map_error(fn(error) {
    acumen.JsonParseError(utils.json_parse_error_message(
      "authorization",
      error:,
    ))
  })
}

fn status_decoder() -> decode.Decoder(Status) {
  use string <- decode.then(decode.string)
  case string {
    "pending" -> decode.success(Pending)
    "valid" -> decode.success(Valid)
    "invalid" -> decode.success(Invalid)
    "deactivated" -> decode.success(Deactivated)
    "expired" -> decode.success(Expired)
    "revoked" -> decode.success(Revoked)
    _ -> decode.failure(Pending, "AuthorizationStatus")
  }
}
