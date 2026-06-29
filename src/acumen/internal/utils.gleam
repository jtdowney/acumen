import acumen/internal/constants
import acumen/url.{type Url}
import gleam/dynamic/decode
import gleam/http/request.{type Request}
import gleam/int
import gleam/json
import gleam/option
import gleam/time/timestamp.{type Timestamp}
import gleam/uri.{type Uri}
import gose

pub fn gose_error_to_string(err: gose.GoseError) -> String {
  case err {
    gose.ParseError(msg) -> "parse error: " <> msg
    gose.CryptoError(msg) -> "crypto error: " <> msg
    gose.InvalidState(msg) -> "invalid state: " <> msg
    gose.VerificationFailed -> "verification failed"
  }
}

pub fn json_parse_error_message(
  entity: String,
  error error: json.DecodeError,
) -> String {
  let detail = case error {
    json.UnexpectedEndOfInput -> "unexpected end of input"
    json.UnexpectedByte(b) -> "unexpected byte: " <> b
    json.UnexpectedSequence(s) -> "unexpected sequence: " <> s
    json.UnableToDecode([decode.DecodeError(expected:, found:, ..), ..]) ->
      "unable to decode: expected " <> expected <> ", found " <> found
    json.UnableToDecode(_) -> "unable to decode"
  }
  "failed to parse " <> entity <> ": " <> detail
}

pub fn parse_absolute_uri(string: String) -> Result(Uri, Nil) {
  case uri.parse(string) {
    Ok(uri.Uri(scheme: option.Some(_), ..) as parsed) -> Ok(parsed)
    _ -> Error(Nil)
  }
}

pub fn request_from_url(url: Url) -> Request(String) {
  let assert Ok(req) =
    url
    |> url.to_uri
    |> request.from_uri

  req
  |> request.set_header("user-agent", "acumen/" <> constants.version)
  |> request.set_header("accept-language", "en")
}

pub fn timestamp_decoder() -> decode.Decoder(Timestamp) {
  use string <- decode.then(decode.string)
  case timestamp.parse_rfc3339(string) {
    Ok(ts) -> decode.success(ts)
    Error(_) -> decode.failure(timestamp.from_unix_seconds(0), "Timestamp")
  }
}

pub fn unexpected_status_message(status: Int) -> String {
  "unexpected status: " <> int.to_string(status)
}

pub fn uri_decoder() -> decode.Decoder(Uri) {
  use string <- decode.then(decode.string)
  case parse_absolute_uri(string) {
    Ok(parsed) -> decode.success(parsed)
    Error(_) -> decode.failure(uri.empty, "URI")
  }
}
