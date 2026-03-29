import acumen
import acumen/fetch_renewal_info
import acumen/renewal_info
import gleam/http
import gleam/http/response
import gleam/json
import gleam/option
import gleam/time/timestamp
import gleam/uri
import support/fixtures

pub fn build_creates_get_to_renewal_info_url_test() {
  let assert Ok(ri_uri) = uri.parse("https://example.com/renewal-info")
  let directory =
    acumen.Directory(
      ..fixtures.test_directory(),
      renewal_info: option.Some(ri_uri),
    )

  let assert Ok(req) =
    fetch_renewal_info.build(directory, "aYhba4dGQEHPTBhac0U2nY0.AAABkNRR7v4")

  assert req.method == http.Get
  assert req.host == "example.com"
  assert req.path == "/renewal-info/aYhba4dGQEHPTBhac0U2nY0.AAABkNRR7v4"
}

pub fn build_normalizes_trailing_slash_test() {
  let assert Ok(ri_uri) = uri.parse("https://example.com/renewal-info/")
  let directory =
    acumen.Directory(
      ..fixtures.test_directory(),
      renewal_info: option.Some(ri_uri),
    )

  let assert Ok(req) =
    fetch_renewal_info.build(directory, "aYhba4dGQEHPTBhac0U2nY0.AAABkNRR7v4")

  assert req.path == "/renewal-info/aYhba4dGQEHPTBhac0U2nY0.AAABkNRR7v4"
}

pub fn build_returns_error_when_no_renewal_info_endpoint_test() {
  let directory = fixtures.test_directory()
  let assert Error(acumen.InvalidRequest(msg)) =
    fetch_renewal_info.build(directory, "some.certid")
  assert msg == "directory does not include renewalInfo endpoint"
}

pub fn response_parses_renewal_info_test() {
  let body =
    json.object([
      #(
        "suggestedWindow",
        json.object([
          #("start", json.string("2026-01-01T00:00:00Z")),
          #("end", json.string("2026-01-08T00:00:00Z")),
        ]),
      ),
    ])
    |> json.to_string

  let resp =
    response.new(200)
    |> response.set_body(body)

  let assert Ok(info) = fetch_renewal_info.response(resp)

  let expected_start = timestamp.from_unix_seconds(1_767_225_600)
  let expected_end = timestamp.from_unix_seconds(1_767_830_400)
  assert info.suggested_window
    == renewal_info.SuggestedWindow(start: expected_start, end: expected_end)
  assert info.explanation_url == option.None
}

pub fn response_parses_renewal_info_with_explanation_url_test() {
  let body =
    json.object([
      #(
        "suggestedWindow",
        json.object([
          #("start", json.string("2026-01-01T00:00:00Z")),
          #("end", json.string("2026-01-08T00:00:00Z")),
        ]),
      ),
      #("explanationURL", json.string("https://example.com/renewal-info")),
    ])
    |> json.to_string

  let resp =
    response.new(200)
    |> response.set_body(body)

  let assert Ok(info) = fetch_renewal_info.response(resp)

  let assert Ok(expected_url) = uri.parse("https://example.com/renewal-info")
  assert info.explanation_url == option.Some(expected_url)
}

pub fn response_parses_acme_error_for_non_200_status_test() {
  let body =
    json.object([
      #("type", json.string("urn:ietf:params:acme:error:unauthorized")),
      #("detail", json.string("certificate not found")),
    ])
    |> json.to_string

  let resp =
    response.new(404)
    |> response.set_body(body)

  let assert Error(acumen.Unauthorized(detail)) =
    fetch_renewal_info.response(resp)
  assert detail == "certificate not found"
}

pub fn response_returns_json_error_for_non_200_with_bad_body_test() {
  let resp =
    response.new(500)
    |> response.set_body("not json")

  let assert Error(acumen.JsonParseError(_)) = fetch_renewal_info.response(resp)
}

pub fn response_rejects_malformed_json_test() {
  let resp =
    response.new(200)
    |> response.set_body("not json")

  let assert Error(acumen.JsonParseError(_)) = fetch_renewal_info.response(resp)
}
