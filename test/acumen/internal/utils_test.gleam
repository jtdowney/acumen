import acumen/internal/utils
import gleam/dynamic
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/duration
import gleam/time/timestamp
import gleam/uri
import gose
import qcheck

pub fn uri_decoder_parses_valid_url_test() {
  let result =
    decode.run(dynamic.string("https://example.com/path"), utils.uri_decoder())
    |> result.replace_error(Nil)

  assert result == uri.parse("https://example.com/path")
}

pub fn uri_decoder_rejects_invalid_port_test() {
  let result =
    decode.run(dynamic.string("https://example.com:abc"), utils.uri_decoder())

  assert result == Error([decode.DecodeError("URI", "String", [])])
}

pub fn timestamp_decoder_parses_rfc3339_test() {
  let result =
    decode.run(
      dynamic.string("2024-01-15T10:30:00Z"),
      utils.timestamp_decoder(),
    )

  let assert Ok(ts) = result
  let assert Ok(expected) = timestamp.parse_rfc3339("2024-01-15T10:30:00Z")
  assert ts == expected
}

pub fn timestamp_decoder_parses_with_offset_test() {
  let result =
    decode.run(
      dynamic.string("2024-01-15T10:30:00+05:00"),
      utils.timestamp_decoder(),
    )

  let assert Ok(ts) = result
  let assert Ok(expected) = timestamp.parse_rfc3339("2024-01-15T10:30:00+05:00")
  assert ts == expected
}

pub fn timestamp_decoder_rejects_invalid_format_test() {
  let result =
    decode.run(dynamic.string("not-a-timestamp"), utils.timestamp_decoder())

  assert result == Error([decode.DecodeError("Timestamp", "String", [])])
}

pub fn uri_decoder_roundtrip_property_test() {
  use #(domain, path) <- qcheck.given(qcheck.tuple2(
    qcheck.non_empty_string_from(qcheck.alphabetic_ascii_codepoint()),
    qcheck.string_from(qcheck.alphanumeric_ascii_codepoint()),
  ))

  let url = "https://" <> domain <> ".com/" <> path
  let result =
    decode.run(dynamic.string(url), utils.uri_decoder())
    |> result.replace_error(Nil)
  let expected = uri.parse(url)

  assert result == expected
}

pub fn gose_error_to_string_parse_error_test() {
  assert utils.gose_error_to_string(gose.ParseError("bad input"))
    == "parse error: bad input"
}

pub fn gose_error_to_string_crypto_error_test() {
  assert utils.gose_error_to_string(gose.CryptoError("key failed"))
    == "crypto error: key failed"
}

pub fn gose_error_to_string_invalid_state_test() {
  assert utils.gose_error_to_string(gose.InvalidState("wrong state"))
    == "invalid state: wrong state"
}

pub fn gose_error_to_string_verification_failed_test() {
  assert utils.gose_error_to_string(gose.VerificationFailed)
    == "verification failed"
}

pub fn uri_decoder_rejects_missing_scheme_test() {
  let result =
    decode.run(dynamic.string("//example.com/path"), utils.uri_decoder())

  assert result == Error([decode.DecodeError("URI", "String", [])])
}

pub fn uri_decoder_accepts_non_http_scheme_test() {
  let result =
    decode.run(dynamic.string("ftp://example.com/path"), utils.uri_decoder())
    |> result.replace_error(Nil)

  assert result == uri.parse("ftp://example.com/path")
}

pub fn uri_decoder_accepts_data_uri_test() {
  let result =
    decode.run(dynamic.string("data:text/plain,hello"), utils.uri_decoder())
    |> result.replace_error(Nil)

  assert result == uri.parse("data:text/plain,hello")
}

pub fn parse_absolute_uri_rejects_missing_scheme_test() {
  assert utils.parse_absolute_uri("//example.com/path") == Error(Nil)
}

pub fn parse_absolute_uri_roundtrip_property_test() {
  use #(scheme, domain, path) <- qcheck.given(qcheck.tuple3(
    qcheck.from_generators(qcheck.return("https"), [
      qcheck.return("http"),
    ]),
    qcheck.non_empty_string_from(qcheck.alphabetic_ascii_codepoint()),
    qcheck.string_from(qcheck.alphanumeric_ascii_codepoint()),
  ))

  let url = scheme <> "://" <> domain <> ".com/" <> path
  let result = utils.parse_absolute_uri(url) |> result.replace_error(Nil)
  let expected = uri.parse(url)

  assert result == expected
}

pub fn unexpected_status_message_test() {
  assert utils.unexpected_status_message(404) == "unexpected status: 404"
}

pub fn json_parse_error_message_test() {
  assert utils.json_parse_error_message(
      "directory",
      error: json.UnexpectedEndOfInput,
    )
    == "failed to parse directory: unexpected end of input"
}

pub fn json_parse_error_message_unexpected_byte_test() {
  assert utils.json_parse_error_message(
      "order",
      error: json.UnexpectedByte("x"),
    )
    == "failed to parse order: unexpected byte: x"
}

pub fn parse_http_date_parses_rfc1123_test() {
  let assert Ok(ts) = utils.parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT")
  let #(unix_seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(ts)
  assert unix_seconds == 784_111_777
}

pub fn parse_http_date_rejects_too_few_tokens_test() {
  assert utils.parse_http_date("Sun, 06 Nov 1994") == Error(Nil)
}

pub fn parse_http_date_rejects_non_numeric_day_test() {
  assert utils.parse_http_date("Sun, XX Nov 1994 08:49:37 GMT") == Error(Nil)
}

pub fn parse_http_date_rejects_non_numeric_year_test() {
  assert utils.parse_http_date("Sun, 06 Nov XXXX 08:49:37 GMT") == Error(Nil)
}

pub fn parse_http_date_rejects_malformed_time_test() {
  assert utils.parse_http_date("Sun, 06 Nov 1994 08:49 GMT") == Error(Nil)
}

pub fn parse_http_date_rejects_non_numeric_time_test() {
  assert utils.parse_http_date("Sun, 06 Nov 1994 XX:49:37 GMT") == Error(Nil)
}

pub fn parse_http_date_rejects_invalid_month_test() {
  assert utils.parse_http_date("Sun, 06 Xyz 1994 08:49:37 GMT") == Error(Nil)
}

pub fn parse_http_date_roundtrip_property_test() {
  let month_gen =
    qcheck.from_generators(qcheck.return(#("Jan", calendar.January)), [
      qcheck.return(#("Feb", calendar.February)),
      qcheck.return(#("Mar", calendar.March)),
      qcheck.return(#("Apr", calendar.April)),
      qcheck.return(#("May", calendar.May)),
      qcheck.return(#("Jun", calendar.June)),
      qcheck.return(#("Jul", calendar.July)),
      qcheck.return(#("Aug", calendar.August)),
      qcheck.return(#("Sep", calendar.September)),
      qcheck.return(#("Oct", calendar.October)),
      qcheck.return(#("Nov", calendar.November)),
      qcheck.return(#("Dec", calendar.December)),
    ])

  use #(#(day, #(month_str, expected_month), year), #(hours, minutes, seconds)) <- qcheck.given(
    qcheck.tuple2(
      qcheck.tuple3(
        qcheck.bounded_int(from: 1, to: 28),
        month_gen,
        qcheck.bounded_int(from: 2000, to: 2050),
      ),
      qcheck.tuple3(
        qcheck.bounded_int(from: 0, to: 23),
        qcheck.bounded_int(from: 0, to: 59),
        qcheck.bounded_int(from: 0, to: 59),
      ),
    ),
  )

  let pad2 = fn(n) { string.pad_start(int.to_string(n), 2, "0") }
  let date_str =
    "Mon, "
    <> pad2(day)
    <> " "
    <> month_str
    <> " "
    <> int.to_string(year)
    <> " "
    <> pad2(hours)
    <> ":"
    <> pad2(minutes)
    <> ":"
    <> pad2(seconds)
    <> " GMT"

  let assert Ok(ts) = utils.parse_http_date(date_str)
  let #(date, time) = timestamp.to_calendar(ts, duration.seconds(0))

  assert date.year == year
  assert date.month == expected_month
  assert date.day == day
  assert time.hours == hours
  assert time.minutes == minutes
  assert time.seconds == seconds
}
