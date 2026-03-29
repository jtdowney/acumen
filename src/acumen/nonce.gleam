//// Nonce fetching for ACME replay protection.
////
//// ACME uses nonces to prevent replay attacks. Every request to the ACME server
//// must include a fresh nonce, and every response includes a new nonce for the
//// next request.
////
//// ## Usage
////
//// You need to fetch an initial nonce before making your first ACME request:
////
//// ```gleam
//// import acumen
//// import acumen/nonce
//// import gleam/httpc
////
//// // After fetching the directory...
//// let assert Ok(nonce_req) = nonce.build(directory)
//// let assert Ok(resp) = httpc.send(nonce_req)
//// let assert Ok(initial_nonce) = nonce.response(resp)
////
//// let ctx = acumen.Context(directory:, nonce: initial_nonce)
//// ```
////
//// After the initial nonce, subsequent nonces are handled automatically by
//// `acumen.execute`, which extracts nonces from response headers and updates
//// the context.
////
//// ## Extracting Nonces from Any Response
////
//// The `response` function can extract a nonce from any ACME response, not
//// just dedicated nonce responses. This is useful if you need to manually
//// manage nonces outside of the `execute` flow.

import acumen
import acumen/internal/utils
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/result

/// Builds an HTTP HEAD request to the directory's `newNonce` endpoint.
pub fn build(directory: acumen.Directory) -> Request(String) {
  utils.request_from_url(directory.new_nonce)
  |> request.set_method(http.Head)
}

/// Extracts a nonce from any ACME response's `Replay-Nonce` header.
///
/// When using `acumen.execute`, nonce extraction is handled automatically.
pub fn response(resp: Response(a)) -> Result(String, acumen.AcmeError) {
  response.get_header(resp, "replay-nonce")
  |> result.replace_error(acumen.InvalidResponse("missing Replay-Nonce header"))
}
