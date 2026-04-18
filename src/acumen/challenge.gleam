//// Challenge types for ACME domain validation.
////
//// After creating an order, complete challenges to prove control over the
//// requested identifiers.

import acumen
import acumen/internal/utils
import acumen/url.{type Url}
import gleam/bit_array
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string
import gleam/time/timestamp.{type Timestamp}
import gose/jose/jwk
import kryptos/crypto
import kryptos/hash
import thirtytwo

/// An ACME challenge for domain validation.
///
/// Each variant represents a specific challenge type with its required fields.
/// Unknown challenge types are ignored during decoding.
pub type Challenge {
  /// HTTP-01: serve a file at `/.well-known/acme-challenge/{token}`.
  Http01Challenge(
    url: Url,
    status: Status,
    token: String,
    validated: Option(Timestamp),
    error: Option(acumen.AcmeError),
  )
  /// DNS-01: create a TXT record at `_acme-challenge.{domain}`.
  Dns01Challenge(
    url: Url,
    status: Status,
    token: String,
    validated: Option(Timestamp),
    error: Option(acumen.AcmeError),
  )
  /// TLS-ALPN-01: respond to the `acme-tls/1` ALPN protocol.
  TlsAlpn01Challenge(
    url: Url,
    status: Status,
    token: String,
    validated: Option(Timestamp),
    error: Option(acumen.AcmeError),
  )
  /// DNS-Account-01: create an account-scoped DNS TXT record.
  DnsAccount01Challenge(
    url: Url,
    status: Status,
    token: String,
    validated: Option(Timestamp),
    error: Option(acumen.AcmeError),
  )
  /// DNS-Persist-01: create a persistent TXT record at `_validation-persist.{domain}`.
  DnsPersist01Challenge(
    url: Url,
    status: Status,
    validated: Option(Timestamp),
    error: Option(acumen.AcmeError),
    issuer_domain_names: List(String),
  )
}

/// Known ACME challenge types for use with `find_by_type`.
pub type ChallengeType {
  /// HTTP-01 challenge type.
  Http01
  /// DNS-01 challenge type.
  Dns01
  /// TLS-ALPN-01 challenge type.
  TlsAlpn01
  /// DNS-Persist-01 challenge type.
  DnsPersist01
  /// DNS-Account-01 challenge type.
  DnsAccount01
}

/// Challenge status.
pub type Status {
  /// Challenge is waiting to be validated.
  Pending
  /// Server is attempting validation.
  Processing
  /// Challenge completed successfully.
  Valid
  /// Challenge failed.
  Invalid
}

/// Computes the DNS-01 TXT record value.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(key_auth) = challenge.key_authorization(dns_challenge, registered_key)
/// let assert Ok(txt_value) = challenge.dns01_txt_record(key_auth)
/// // Create TXT record: _acme-challenge.example.com -> txt_value
/// ```
pub fn dns01_txt_record(
  key_authorization: String,
) -> Result(String, acumen.AcmeError) {
  crypto.hash(hash.Sha256, bit_array.from_string(key_authorization))
  |> result.map(fn(digest) { bit_array.base64_url_encode(digest, False) })
  |> result.replace_error(acumen.CryptoError("SHA-256 hash failed"))
}

/// Computes the DNS-Account-01 TXT record name and value.
///
/// Returns `#(name, value)` where `name` is the full record name and
/// `value` is the record content.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(key_auth) = challenge.key_authorization(dns_acct_challenge, registered_key)
/// let assert Ok(#(record_name, record_value)) =
///   challenge.dns_account01_txt_record("example.com", registered_key.kid, key_auth)
/// // Create TXT record: record_name -> record_value
/// ```
pub fn dns_account01_txt_record(
  for domain: String,
  account_url account_url: Url,
  key_authorization key_authorization: String,
) -> Result(#(String, String), acumen.AcmeError) {
  use label <- result.try(dns_account_label(url.to_string(account_url)))
  use value <- result.try(dns01_txt_record(key_authorization))
  let name = "_acme-challenge_" <> label <> "." <> domain
  Ok(#(name, value))
}

/// Builds a DNS-Persist-01 TXT record value for a single issuer.
///
/// A DNS-Persist-01 challenge may include multiple issuer domain names.
/// Callers should create a separate TXT record for each issuer, all on the
/// same `_validation-persist.{domain}` DNS name.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(issuers) = challenge.issuer_domain_names(dns_persist_challenge)
/// let txt_records = list.map(issuers, fn(issuer) {
///   challenge.dns_persist01_txt_record(issuer:, account_url: registered_key.kid)
/// })
/// // Create a TXT record at _validation-persist.example.com for each value
/// ```
pub fn dns_persist01_txt_record(
  issuer issuer_domain_name: String,
  account_url account_url: Url,
) -> String {
  issuer_domain_name <> "; accounturi=" <> url.to_string(account_url)
}

/// Finds the first challenge matching the given type, or `Error(Nil)` if none.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(http_challenge) =
///   challenge.find_by_type(authorization.challenges, of: challenge.Http01)
/// ```
pub fn find_by_type(
  challenges: List(Challenge),
  of type_: ChallengeType,
) -> Result(Challenge, Nil) {
  list.find(challenges, fn(c) { challenge_type_of(c) == type_ })
}

/// Returns the issuer domain names for a DNS-Persist-01 challenge.
///
/// Returns `Error(Nil)` for other challenge types.
pub fn issuer_domain_names(challenge: Challenge) -> Result(List(String), Nil) {
  case challenge {
    DnsPersist01Challenge(issuer_domain_names:, ..) -> Ok(issuer_domain_names)
    Http01Challenge(..)
    | Dns01Challenge(..)
    | TlsAlpn01Challenge(..)
    | DnsAccount01Challenge(..) -> Error(Nil)
  }
}

/// Computes the key authorization string for a challenge.
///
/// Returns `Error(acumen.InvalidChallenge(_))` for challenge types that
/// don't have a token (e.g., `DnsPersist01Challenge`).
///
/// ## Example
///
/// ```gleam
/// let assert Ok(key_auth) = challenge.key_authorization(http_challenge, registered_key)
/// // Deploy: GET /.well-known/acme-challenge/{token} -> key_auth
/// ```
pub fn key_authorization(
  challenge: Challenge,
  key: acumen.RegisteredKey,
) -> Result(String, acumen.AcmeError) {
  use tkn <- result.try(
    token(challenge)
    |> result.replace_error(acumen.InvalidChallenge(
      "Challenge type does not have a token",
    )),
  )

  jwk.thumbprint(key.jwk, hash.Sha256)
  |> result.map_error(fn(err) {
    acumen.CryptoError(utils.gose_error_to_string(err))
  })
  |> result.map(fn(thumbprint) { tkn <> "." <> thumbprint })
}

/// Returns the status of a challenge.
pub fn status(challenge: Challenge) -> Status {
  challenge.status
}

/// Returns the token for a challenge.
///
/// Returns `Error(Nil)` for challenge types without a token (e.g. DNS-Persist-01).
pub fn token(challenge: Challenge) -> Result(String, Nil) {
  case challenge {
    Http01Challenge(token:, ..) -> Ok(token)
    Dns01Challenge(token:, ..) -> Ok(token)
    TlsAlpn01Challenge(token:, ..) -> Ok(token)
    DnsAccount01Challenge(token:, ..) -> Ok(token)
    DnsPersist01Challenge(..) -> Error(Nil)
  }
}

/// Returns the URL for a challenge.
pub fn url(challenge: Challenge) -> Url {
  challenge.url
}

@internal
pub fn challenge_type_of(challenge: Challenge) -> ChallengeType {
  case challenge {
    Http01Challenge(..) -> Http01
    Dns01Challenge(..) -> Dns01
    TlsAlpn01Challenge(..) -> TlsAlpn01
    DnsAccount01Challenge(..) -> DnsAccount01
    DnsPersist01Challenge(..) -> DnsPersist01
  }
}

@internal
pub fn decoder() -> decode.Decoder(Challenge) {
  use type_ <- decode.field("type", decode.string)
  case type_ {
    "http-01" -> standard_challenge_decoder(Http01Challenge)
    "dns-01" -> standard_challenge_decoder(Dns01Challenge)
    "tls-alpn-01" -> standard_challenge_decoder(TlsAlpn01Challenge)
    "dns-persist-01" -> dns_persist_challenge_decoder()
    "dns-account-01" -> standard_challenge_decoder(DnsAccount01Challenge)
    _ -> {
      let assert Ok(placeholder) = url.from_string("https://placeholder")
      decode.failure(
        Http01Challenge(
          url: placeholder,
          status: Pending,
          token: "",
          validated: option.None,
          error: option.None,
        ),
        "Challenge",
      )
    }
  }
}

@internal
pub fn optional_decoder() -> decode.Decoder(Option(Challenge)) {
  use type_ <- decode.field("type", decode.string)
  case type_ {
    "http-01" ->
      standard_challenge_decoder(Http01Challenge) |> decode.map(option.Some)
    "dns-01" ->
      standard_challenge_decoder(Dns01Challenge) |> decode.map(option.Some)
    "tls-alpn-01" ->
      standard_challenge_decoder(TlsAlpn01Challenge) |> decode.map(option.Some)
    "dns-persist-01" ->
      dns_persist_challenge_decoder() |> decode.map(option.Some)
    "dns-account-01" ->
      standard_challenge_decoder(DnsAccount01Challenge)
      |> decode.map(option.Some)
    _ -> decode.success(option.None)
  }
}

fn dns_persist_challenge_decoder() -> decode.Decoder(Challenge) {
  use url <- decode.field("url", url.decoder())
  use status <- decode.field("status", status_decoder())
  use validated <- decode.optional_field(
    "validated",
    option.None,
    decode.optional(utils.timestamp_decoder()),
  )
  use error <- decode.optional_field("error", option.None, error_decoder())
  use issuer_domain_names <- decode.field(
    "issuer-domain-names",
    decode.list(decode.string),
  )
  decode.success(DnsPersist01Challenge(
    url:,
    status:,
    validated:,
    error:,
    issuer_domain_names:,
  ))
}

fn standard_challenge_decoder(
  constructor: fn(
    Url,
    Status,
    String,
    Option(Timestamp),
    Option(acumen.AcmeError),
  ) ->
    Challenge,
) -> decode.Decoder(Challenge) {
  use url <- decode.field("url", url.decoder())
  use status <- decode.field("status", status_decoder())
  use token <- decode.field("token", decode.string)
  use validated <- decode.optional_field(
    "validated",
    option.None,
    decode.optional(utils.timestamp_decoder()),
  )
  use error <- decode.optional_field("error", option.None, error_decoder())
  decode.success(constructor(url, status, token, validated, error))
}

/// Computes the DNS-Account-01 label derived from an account URL.
///
/// The label is `lowercase(base32(SHA-256(account_url)[0:10]))` per the
/// dns-account-01 specification.
@internal
pub fn dns_account_label(
  account_url: String,
) -> Result(String, acumen.AcmeError) {
  case crypto.hash(hash.Sha256, bit_array.from_string(account_url)) {
    Error(_) -> Error(acumen.CryptoError("SHA-256 hash failed"))
    Ok(<<prefix:bytes-size(10), _:bits>>) -> {
      let label =
        prefix
        |> thirtytwo.encode(padding: False)
        |> string.lowercase()
      Ok(label)
    }
    Ok(_) -> Error(acumen.CryptoError("unexpected hash digest length"))
  }
}

@internal
pub fn error_decoder() -> decode.Decoder(Option(acumen.AcmeError)) {
  decode.optional({
    use type_ <- decode.field("type", decode.string)
    use detail <- decode.optional_field("detail", "", decode.string)
    use instance <- decode.optional_field(
      "instance",
      option.None,
      decode.optional(decode.string),
    )
    use subproblems <- decode.optional_field(
      "subproblems",
      [],
      decode.list(acumen.subproblem_decoder()),
    )
    decode.success(acumen.acme_error_from_type(
      type_,
      detail,
      instance,
      subproblems,
      option.None,
    ))
  })
}

fn status_decoder() -> decode.Decoder(Status) {
  use string <- decode.then(decode.string)
  case string {
    "pending" -> decode.success(Pending)
    "processing" -> decode.success(Processing)
    "valid" -> decode.success(Valid)
    "invalid" -> decode.success(Invalid)
    _ -> decode.failure(Pending, "ChallengeStatus")
  }
}
