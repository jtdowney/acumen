import acumen
import acumen/nonce
import gleam/http
import gleam/http/response
import support/fixtures

pub fn request_creates_head_to_new_nonce_test() {
  let directory = fixtures.test_directory()
  let req = nonce.build(directory)

  assert req.method == http.Head
  assert req.host == "example.com"
  assert req.path == "/endpoint"
}

pub fn response_extracts_replay_nonce_header_test() {
  let resp =
    response.new(200)
    |> response.set_header("replay-nonce", "test-nonce-value")
    |> response.set_body("")

  let assert Ok(nonce_value) = nonce.response(resp)
  assert nonce_value == "test-nonce-value"
}

pub fn response_returns_error_when_header_missing_test() {
  let resp =
    response.new(200)
    |> response.set_body("")

  let assert Error(acumen.InvalidResponse(msg)) = nonce.response(resp)
  assert msg == "missing Replay-Nonce header"
}
