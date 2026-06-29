import acumen/internal/utils
import gleam/dynamic
import gleam/dynamic/decode
import gleam/json
import gleam/result
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
