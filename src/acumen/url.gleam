//// A URL type that preserves the original server-provided string.
////
//// ACME servers provide URLs in JSON responses and HTTP headers. RFC 8555
//// Section 6.4 requires the exact server-provided string in signed JWS
//// headers. This type stores the raw string alongside the parsed URI so
//// that serialization never alters the URL.

import gleam/dynamic/decode
import gleam/option
import gleam/uri.{type Uri}

/// A validated HTTP(S) URL that preserves the original string.
///
/// Use `to_string` when the exact server-provided string is needed
/// (JWS signing, JSON serialization). Use `to_uri` when URI components
/// (host, path, scheme) are needed (HTTP request building).
pub opaque type Url {
  Url(raw: String, parsed: Uri)
}

/// Parses a string into a `Url`.
///
/// Succeeds only for absolute HTTPS URLs with a host.
pub fn from_string(string: String) -> Result(Url, Nil) {
  case uri.parse(string) {
    Ok(
      uri.Uri(scheme: option.Some("https"), host: option.Some(h), ..) as parsed,
    )
      if h != ""
    -> Ok(Url(raw: string, parsed:))
    _ -> Error(Nil)
  }
}

/// Returns the original string, byte-for-byte as received.
pub fn to_string(url: Url) -> String {
  url.raw
}

/// Returns the parsed URI for component access.
pub fn to_uri(url: Url) -> Uri {
  url.parsed
}

/// JSON decoder for ACME URL fields.
pub fn decoder() -> decode.Decoder(Url) {
  use string <- decode.then(decode.string)
  case from_string(string) {
    Ok(url) -> decode.success(url)
    Error(_) -> decode.failure(Url(raw: "", parsed: uri.empty), "Url")
  }
}
