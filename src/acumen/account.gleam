//// Account types for ACME.
////
//// An account represents your identity with the ACME server and is required
//// for all certificate operations.

import acumen/url
import gleam/dynamic/decode
import gleam/option.{type Option}

/// An ACME account registered with the server.
pub type Account {
  Account(
    /// Current account status.
    status: Status,
    /// Contact URLs, typically `mailto:` addresses.
    contacts: List(String),
    /// URL to list the account's orders.
    orders_url: Option(url.Url),
    /// Whether the terms of service were agreed to.
    terms_of_service_agreed: Option(Bool),
  )
}

/// Account status.
pub type Status {
  /// The account is active and can be used.
  Valid
  /// The account was deactivated by the user.
  Deactivated
  /// The account was revoked by the server.
  Revoked
}

/// External account binding credentials from the CA.
///
/// Some CAs (like Google, ZeroSSL) require you to link your ACME account
/// to an existing account with them. They provide a key ID and MAC key
/// that you use during registration.
pub type ExternalAccountBinding {
  ExternalAccountBinding(
    /// The key ID provided by the CA
    key_id: String,
    /// The MAC key (decoded from base64url) for HMAC signing
    mac_key: BitArray,
  )
}

@internal
pub fn decoder() -> decode.Decoder(Account) {
  use status <- decode.field("status", status_decoder())
  use contacts <- decode.optional_field(
    "contact",
    [],
    decode.list(decode.string),
  )
  use orders_url <- decode.optional_field(
    "orders",
    option.None,
    decode.optional(url.decoder()),
  )
  use tos_agreed <- decode.optional_field(
    "termsOfServiceAgreed",
    option.None,
    decode.optional(decode.bool),
  )
  decode.success(Account(
    status:,
    contacts:,
    orders_url:,
    terms_of_service_agreed: tos_agreed,
  ))
}

fn status_decoder() -> decode.Decoder(Status) {
  use string <- decode.then(decode.string)
  case string {
    "valid" -> decode.success(Valid)
    "deactivated" -> decode.success(Deactivated)
    "revoked" -> decode.success(Revoked)
    _ -> decode.failure(Valid, "Status")
  }
}
