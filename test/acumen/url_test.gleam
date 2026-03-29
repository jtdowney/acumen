import acumen/url
import gleam/dynamic
import gleam/dynamic/decode
import gleam/option
import qcheck

pub fn from_string_accepts_https_test() {
  let assert Ok(u) = url.from_string("https://example.com/path")
  assert url.to_string(u) == "https://example.com/path"
}

pub fn from_string_rejects_http_test() {
  assert url.from_string("http://example.com/path") == Error(Nil)
}

pub fn from_string_rejects_no_scheme_test() {
  assert url.from_string("//example.com/path") == Error(Nil)
}

pub fn from_string_rejects_non_http_scheme_test() {
  assert url.from_string("ftp://example.com/path") == Error(Nil)
}

pub fn from_string_rejects_no_host_test() {
  assert url.from_string("https:///path") == Error(Nil)
}

pub fn from_string_rejects_relative_path_test() {
  assert url.from_string("/path/only") == Error(Nil)
}

pub fn to_string_preserves_raw_string_test() {
  let raw = "https://example.com:8443/path?query=1#frag"
  let assert Ok(u) = url.from_string(raw)
  assert url.to_string(u) == raw
}

pub fn to_uri_exposes_parsed_components_test() {
  let assert Ok(u) = url.from_string("https://example.com/path")
  let parsed = url.to_uri(u)
  assert parsed.host == option.Some("example.com")
  assert parsed.path == "/path"
  assert parsed.scheme == option.Some("https")
}

pub fn decoder_succeeds_for_valid_url_test() {
  let assert Ok(u) =
    decode.run(dynamic.string("https://example.com/path"), url.decoder())
  assert url.to_string(u) == "https://example.com/path"
}

pub fn decoder_fails_for_invalid_url_test() {
  let assert Error(_) =
    decode.run(dynamic.string("ftp://example.com"), url.decoder())
}

pub fn roundtrip_preserves_string_property_test() {
  let url_gen =
    qcheck.non_empty_string_from(qcheck.alphanumeric_ascii_codepoint())
    |> qcheck.map(fn(path) { "https://example.com/" <> path })

  use raw <- qcheck.given(url_gen)
  let assert Ok(u) = url.from_string(raw)
  assert url.to_string(u) == raw
}

pub fn from_string_rejects_data_uri_test() {
  assert url.from_string("data:text/plain,hello") == Error(Nil)
}

pub fn from_string_rejects_empty_string_test() {
  assert url.from_string("") == Error(Nil)
}

pub fn from_string_accepts_url_with_port_test() {
  let assert Ok(u) = url.from_string("https://example.com:8443/path")
  let parsed = url.to_uri(u)
  assert parsed.port == option.Some(8443)
}
