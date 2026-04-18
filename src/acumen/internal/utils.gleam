import acumen/internal/constants
import acumen/url.{type Url}
import gleam/bool
import gleam/dynamic/decode
import gleam/http/request.{type Request}
import gleam/int
import gleam/json
import gleam/option
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/duration
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

pub fn parse_http_date(value: String) -> Result(Timestamp, Nil) {
  case string.split(value, " ") {
    [_, day_str, month_str, year_str, time_str, ..] -> {
      use day <- result.try(int.parse(day_str))
      use <- bool.guard(day < 1 || day > 31, Error(Nil))
      use month <- result.try(parse_month(month_str))
      use year <- result.try(int.parse(year_str))
      use #(hours, minutes, seconds) <- result.try(parse_time(time_str))
      use <- bool.guard(hours < 0 || hours > 23, Error(Nil))
      use <- bool.guard(minutes < 0 || minutes > 59, Error(Nil))
      use <- bool.guard(seconds < 0 || seconds > 59, Error(Nil))
      Ok(timestamp.from_calendar(
        date: calendar.Date(year:, month:, day:),
        time: calendar.TimeOfDay(hours:, minutes:, seconds:, nanoseconds: 0),
        offset: duration.seconds(0),
      ))
    }
    _ -> Error(Nil)
  }
}

fn parse_time(time: String) -> Result(#(Int, Int, Int), Nil) {
  case string.split(time, ":") {
    [hours_str, minutes_str, seconds_str] -> {
      use hours <- result.try(int.parse(hours_str))
      use minutes <- result.try(int.parse(minutes_str))
      use seconds <- result.try(int.parse(seconds_str))
      Ok(#(hours, minutes, seconds))
    }
    _ -> Error(Nil)
  }
}

fn parse_month(month: String) -> Result(calendar.Month, Nil) {
  case month {
    "Jan" -> Ok(calendar.January)
    "Feb" -> Ok(calendar.February)
    "Mar" -> Ok(calendar.March)
    "Apr" -> Ok(calendar.April)
    "May" -> Ok(calendar.May)
    "Jun" -> Ok(calendar.June)
    "Jul" -> Ok(calendar.July)
    "Aug" -> Ok(calendar.August)
    "Sep" -> Ok(calendar.September)
    "Oct" -> Ok(calendar.October)
    "Nov" -> Ok(calendar.November)
    "Dec" -> Ok(calendar.December)
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
