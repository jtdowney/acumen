//// Acumen is a Gleam library for interacting with ACME servers (such as Let's
//// Encrypt) to automate certificate issuance and management.
////
//// ## Architecture
////
//// Acumen uses a **sans-IO** pattern, meaning it produces HTTP request descriptions
//// and consumes response data rather than performing I/O directly. This makes it:
////
//// - **HTTP client agnostic**: Use any HTTP library (gleam_httpc, gleam_fetch, etc.)
//// - **Target agnostic**: Works on both Erlang VM and JavaScript runtimes
////
//// ## Quick Start
////
//// ```gleam
//// import acumen
//// import acumen/nonce
//// import acumen/register_account
//// import gleam/http/request
//// import gleam/httpc
//// import gose/jwk
//// import kryptos/ec
////
//// pub fn main() {
////   // 1. Fetch the ACME directory
////   let assert Ok(req) = request.to("https://acme-v02.api.letsencrypt.org/directory")
////   let assert Ok(resp) = httpc.send(req)
////   let assert Ok(directory) = acumen.directory(resp)
////
////   // 2. Get an initial nonce
////   let assert Ok(nonce_req) = nonce.build(directory)
////   let assert Ok(nonce_resp) = httpc.send(nonce_req)
////   let assert Ok(initial_nonce) = nonce.response(nonce_resp)
////
////   // 3. Create context and account key
////   let ctx = acumen.Context(directory:, nonce: initial_nonce)
////   let key = jwk.generate_ec(ec.P256)
////   let unregistered = acumen.UnregisteredKey(key)
////
////   // 4. Register an account
////   let reg = register_account.request()
////     |> register_account.contacts(["mailto:admin@example.com"])
////     |> register_account.agree_to_terms
////
////   let assert Ok(#(resp, ctx)) = acumen.execute(
////     ctx,
////     build: register_account.build(reg, _, unregistered),
////     send: httpc.send,
////   )
////
////   let assert Ok(#(account, registered_key)) =
////     register_account.response(resp, unregistered)
//// }
//// ```

import acumen/internal/constants
import acumen/internal/jws
import acumen/internal/utils
import acumen/url.{type Url}
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string
import gleam/time/timestamp.{type Timestamp}
import gleam/uri.{type Uri}
import gose/jwk.{type Jwk}

/// Library version used in User-Agent header.
pub const version = constants.version

const max_nonce_retries = 3

/// All errors that can occur during ACME operations.
pub type AcmeError {
  /// An input value was invalid when building a request (e.g., malformed URI).
  InvalidRequest(message: String)
  /// The server response was malformed or unexpected.
  InvalidResponse(message: String)
  /// JSON decoding failed.
  JsonParseError(message: String)
  /// JWS signing or encoding failed.
  JwsError(message: String)
  /// A cryptographic operation failed (e.g., key thumbprint).
  CryptoError(message: String)
  /// The challenge type does not support the requested operation.
  InvalidChallenge(message: String)
  /// The account does not exist on the server.
  AccountDoesNotExist(detail: String)
  /// The certificate has already been replaced by another order.
  AlreadyReplaced(detail: String)
  /// The certificate was already revoked.
  AlreadyRevoked(detail: String)
  /// The CSR is unacceptable.
  BadCsr(detail: String)
  /// The nonce was invalid. Automatically retried by `execute`.
  BadNonce(detail: String)
  /// The public key is unacceptable.
  BadPublicKey(detail: String)
  /// The revocation reason is unacceptable.
  BadRevocationReason(detail: String)
  /// The JWS algorithm is not supported by the server.
  BadSignatureAlgorithm(detail: String)
  /// CAA records forbid certificate issuance.
  CaaError(detail: String)
  /// Multiple errors occurred; check `subproblems` for details.
  CompoundError(detail: String, subproblems: List(Subproblem))
  /// The server could not connect to the client for validation.
  ConnectionError(detail: String)
  /// A DNS lookup failed during validation.
  DnsError(detail: String)
  /// External account binding is required by the server.
  ExternalAccountRequired(detail: String)
  /// The challenge validation response was incorrect.
  IncorrectResponse(detail: String)
  /// A contact URL in the account is invalid.
  InvalidContact(detail: String)
  /// The request was malformed.
  MalformedError(detail: String)
  /// The order is not ready for finalization.
  OrderNotReady(detail: String)
  /// Too many requests; consider backing off.
  RateLimited(detail: String)
  /// The server will not issue for the requested identifier.
  RejectedIdentifier(detail: String)
  /// An internal server error occurred.
  ServerInternalError(detail: String)
  /// A TLS error occurred during validation.
  TlsError(detail: String)
  /// The client is not authorized for the requested operation.
  Unauthorized(detail: String)
  /// The contact URL scheme is not supported by the server.
  UnsupportedContact(detail: String)
  /// The identifier type is not supported by the server.
  UnsupportedIdentifier(detail: String)
  /// The user must visit a URL to complete an action;
  /// check the `instance` field for the URL.
  UserActionRequired(detail: String, instance: Option(String))
  /// An unrecognized error type from the server.
  UnknownError(type_: String, detail: String, status: Option(Int))
}

/// Lightweight state container for building ACME requests.
///
/// ACME requires a fresh nonce for each request. The `execute` function
/// automatically updates the context with nonces from response headers.
pub type Context {
  Context(
    /// The ACME directory with endpoint URLs.
    directory: Directory,
    /// The current nonce for replay protection.
    nonce: String,
  )
}

/// ACME directory containing endpoint URLs for all ACME operations.
///
/// The directory is fetched once from the ACME server and provides the
/// URLs needed to interact with the ACME API.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(req) = request.to("https://acme-v02.api.letsencrypt.org/directory")
/// let assert Ok(resp) = httpc.send(req)
/// let assert Ok(directory) = acumen.directory(resp)
/// ```
pub type Directory {
  Directory(
    /// URL for fetching replay-protection nonces.
    new_nonce: Url,
    /// URL for account registration.
    new_account: Url,
    /// URL for creating certificate orders.
    new_order: Url,
    /// URL for revoking certificates.
    revoke_cert: Url,
    /// URL for changing account keys.
    key_change: Url,
    /// URL for pre-authorization.
    new_authz: Option(Url),
    /// URL for fetching renewal information.
    renewal_info: Option(Uri),
    /// Optional server metadata (terms of service, CAA identities, etc.).
    meta: Option(DirectoryMeta),
  )
}

/// Optional metadata from the ACME directory.
///
/// Provides additional information about the ACME server's policies
/// and capabilities.
pub type DirectoryMeta {
  DirectoryMeta(
    /// URL for the terms of service that users must agree to.
    terms_of_service: Option(Uri),
    /// Website for the certificate authority.
    website: Option(Uri),
    /// Domain names for DNS CAA record validation.
    caa_identities: List(String),
    /// Whether external account binding is required for registration.
    external_account_required: Bool,
    /// Available certificate issuance profiles.
    profiles: Dict(String, String),
  )
}

/// Errors returned by the `execute` function.
///
/// This type is parameterized by `e`, the error type of your HTTP transport.
pub type ExecuteError(e) {
  /// An ACME protocol error returned by the server.
  ProtocolError(error: AcmeError, context: Context)
  /// An HTTP transport error (e.g., network failure, timeout).
  TransportError(e)
  /// All nonce retry attempts were exhausted.
  NonceRetryExhausted
}

/// An identifier representing a domain name or IP address for certificate issuance.
pub type Identifier {
  /// A DNS identifier representing a fully qualified domain name
  /// (e.g., `"example.com"` or `"*.example.com"` for wildcard certificates).
  DnsIdentifier(value: String)
  /// An IP identifier representing an IPv4 or IPv6 address
  /// (e.g., `"192.0.2.1"` or `"2001:db8::1"`).
  IpIdentifier(value: String)
}

/// An account key that has been registered with the ACME server.
///
/// After successful registration, the key is paired with a `kid` (key ID),
/// which is the account URL.
///
/// The `RegisteredKey` is returned by `register_account.response` after a
/// successful account registration.
pub type RegisteredKey {
  RegisteredKey(jwk: Jwk, kid: Url)
}

/// Parsed Retry-After header value.
///
/// Per RFC 9110, the Retry-After header can be either delta-seconds
/// (an integer) or an HTTP date.
pub type RetryAfter {
  /// Wait this many seconds before retrying.
  RetryAfterSeconds(Int)
  /// Retry after this specific point in time.
  RetryAfterTimestamp(Timestamp)
}

/// A subproblem within a compound ACME error.
///
/// Compound errors contain multiple subproblems, each potentially associated
/// with a specific identifier that caused the issue.
pub type Subproblem {
  Subproblem(type_: String, detail: String, identifier: Option(Identifier))
}

/// An account key that has not yet been registered with the ACME server.
///
/// ## Example
///
/// ```gleam
/// import gose/jwk
/// import kryptos/ec
///
/// let key = jwk.generate_ec(ec.P256)
/// let unregistered = acumen.UnregisteredKey(key)
/// ```
pub type UnregisteredKey {
  UnregisteredKey(jwk: Jwk)
}

/// Parses an ACME directory response.
///
/// The directory is the entry point for all ACME operations. Fetch it with
/// a GET to the server's directory URL.
///
/// ## Example
///
/// ```gleam
/// // Let's Encrypt production
/// let assert Ok(req) = request.to("https://acme-v02.api.letsencrypt.org/directory")
/// let assert Ok(resp) = httpc.send(req)
/// let assert Ok(directory) = acumen.directory(resp)
///
/// // Let's Encrypt staging
/// let assert Ok(req) = request.to("https://acme-staging-v02.api.letsencrypt.org/directory")
/// let assert Ok(resp) = httpc.send(req)
/// let assert Ok(directory) = acumen.directory(resp)
/// ```
pub fn directory(resp: Response(String)) -> Result(Directory, AcmeError) {
  case resp.status {
    200 -> parse_directory_body(resp.body)
    status ->
      Error(InvalidResponse(
        "expected status 200, got " <> int.to_string(status),
      ))
  }
}

fn parse_directory_body(body: String) -> Result(Directory, AcmeError) {
  let decoder = {
    use new_nonce <- decode.field("newNonce", url.decoder())
    use new_account <- decode.field("newAccount", url.decoder())
    use new_order <- decode.field("newOrder", url.decoder())
    use revoke_cert <- decode.field("revokeCert", url.decoder())
    use key_change <- decode.field("keyChange", url.decoder())
    use new_authz <- decode.optional_field(
      "newAuthz",
      option.None,
      decode.optional(url.decoder()),
    )
    use renewal_info <- decode.optional_field(
      "renewalInfo",
      option.None,
      decode.optional(utils.uri_decoder()),
    )
    use meta <- decode.optional_field(
      "meta",
      option.None,
      decode.optional(meta_decoder()),
    )
    decode.success(Directory(
      new_nonce:,
      new_account:,
      new_order:,
      revoke_cert:,
      key_change:,
      new_authz:,
      renewal_info:,
      meta:,
    ))
  }

  json.parse(body, decoder)
  |> result.map_error(fn(error) {
    JsonParseError(utils.json_parse_error_message("directory", error:))
  })
}

fn meta_decoder() -> decode.Decoder(DirectoryMeta) {
  use terms_of_service <- decode.optional_field(
    "termsOfService",
    option.None,
    decode.optional(utils.uri_decoder()),
  )
  use website <- decode.optional_field(
    "website",
    option.None,
    decode.optional(utils.uri_decoder()),
  )
  use caa_identities <- decode.optional_field(
    "caaIdentities",
    [],
    decode.list(decode.string),
  )
  use external_account_required <- decode.optional_field(
    "externalAccountRequired",
    False,
    decode.bool,
  )
  use profiles <- decode.optional_field(
    "profiles",
    dict.new(),
    decode.dict(decode.string, decode.string),
  )
  decode.success(DirectoryMeta(
    terms_of_service:,
    website:,
    caa_identities:,
    external_account_required:,
    profiles:,
  ))
}

/// Executes an ACME request with automatic nonce retry handling.
///
/// Builds the signed request, sends it, and retries on `badNonce` errors
/// (up to 3 retries). Updates the context with fresh nonces from each
/// response.
///
/// ## Example
///
/// ```gleam
/// let registration = register_account.request()
///   |> register_account.contacts(["mailto:admin@example.com"])
///   |> register_account.agree_to_terms
///
/// let result = acumen.execute(
///   ctx,
///   build: register_account.build(registration, _, unregistered_key),
///   send: httpc.send,
/// )
///
/// case result {
///   Ok(#(resp, new_ctx)) -> {
///     // Process successful response
///   }
///   Error(acumen.ProtocolError(error: acumen.RateLimited(_), context: _)) -> {
///     // Back off and retry later
///   }
///   Error(acumen.TransportError(e)) -> {
///     // Handle network error
///   }
///   Error(acumen.NonceRetryExhausted) -> {
///     // All retries failed
///   }
/// }
/// ```
pub fn execute(
  context: Context,
  build build_request: fn(Context) -> Result(Request(String), AcmeError),
  send send: fn(Request(String)) -> Result(Response(String), e),
) -> Result(#(Response(String), Context), ExecuteError(e)) {
  do_execute(context, build_request, send, max_nonce_retries)
}

fn do_execute(
  context: Context,
  build_request: fn(Context) -> Result(Request(String), AcmeError),
  send: fn(Request(String)) -> Result(Response(String), e),
  nonce_retries: Int,
) -> Result(#(Response(String), Context), ExecuteError(e)) {
  use req <- result.try(
    build_request(context)
    |> result.map_error(ProtocolError(_, context)),
  )

  use resp <- result.try(
    send(req)
    |> result.map_error(TransportError),
  )

  let context = case response.get_header(resp, "replay-nonce") {
    Error(Nil) -> context
    Ok(nonce) -> Context(..context, nonce:)
  }

  case resp.status {
    status if status >= 200 && status < 300 -> Ok(#(resp, context))
    400 -> handle_bad_request(resp, context, nonce_retries, build_request, send)
    _ -> parse_error_response(resp, context)
  }
}

fn handle_bad_request(
  resp: Response(String),
  context: Context,
  nonce_retries: Int,
  build_request: fn(Context) -> Result(Request(String), AcmeError),
  send: fn(Request(String)) -> Result(Response(String), e),
) -> Result(#(Response(String), Context), ExecuteError(e)) {
  case parse_error_response(resp, context) {
    Error(ProtocolError(BadNonce(_), _)) if nonce_retries > 0 ->
      do_execute(context, build_request, send, nonce_retries - 1)
    Error(ProtocolError(BadNonce(_), _)) -> Error(NonceRetryExhausted)
    other -> other
  }
}

fn parse_error_response(
  resp: Response(String),
  context: Context,
) -> Result(#(Response(String), Context), ExecuteError(e)) {
  Error(ProtocolError(parse_acme_error(resp), context))
}

@internal
pub fn parse_acme_error(resp: Response(String)) -> AcmeError {
  let decoder = {
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
      decode.list(subproblem_decoder()),
    )
    decode.success(#(type_, detail, instance, subproblems))
  }

  case json.parse(resp.body, decoder) {
    Error(error) ->
      JsonParseError(utils.json_parse_error_message("error response", error:))
    Ok(#(type_, detail, instance, subproblems)) ->
      acme_error_from_type(
        type_,
        detail,
        instance,
        subproblems,
        option.Some(resp.status),
      )
  }
}

/// Returns `True` if the server requires external account binding.
///
/// Returns `False` if the directory has no metadata or the field is not set.
pub fn external_account_required(directory: Directory) -> Bool {
  case directory.meta {
    option.Some(meta) -> meta.external_account_required
    option.None -> False
  }
}

/// Returns available certificate issuance profiles as a dictionary of
/// profile names to descriptions. Empty if the server advertises none.
///
/// ## Example
///
/// ```gleam
/// let available_profiles = acumen.profiles(directory)
/// case dict.get(available_profiles, "tlsserver") {
///   Ok(description) -> io.println("TLS Server profile: " <> description)
///   Error(Nil) -> io.println("TLS Server profile not available")
/// }
/// ```
pub fn profiles(directory: Directory) -> Dict(String, String) {
  case directory.meta {
    option.Some(meta) -> meta.profiles
    option.None -> dict.new()
  }
}

/// Extracts the `Retry-After` header value from a response.
///
/// Handles both delta-seconds and HTTP-date formats per RFC 9110.
///
/// ## Example
///
/// ```gleam
/// case acumen.retry_after(resp) {
///   Ok(acumen.RetryAfterSeconds(seconds)) -> {
///     // Wait for `seconds` before retrying
///   }
///   Ok(acumen.RetryAfterTimestamp(timestamp)) -> {
///     // Retry after `timestamp`
///   }
///   Error(Nil) -> {
///     // No retry-after header, use default backoff
///   }
/// }
/// ```
pub fn retry_after(resp: Response(body)) -> Result(RetryAfter, Nil) {
  use value <- result.try(response.get_header(resp, "retry-after"))
  case int.parse(value) {
    Error(_) ->
      utils.parse_http_date(value)
      |> result.map(RetryAfterTimestamp)
    Ok(seconds) if seconds >= 0 -> Ok(RetryAfterSeconds(seconds))
    Ok(_) -> Error(Nil)
  }
}

/// Returns the terms of service URL from the directory metadata, if present.
pub fn terms_of_service(directory: Directory) -> Result(Uri, Nil) {
  directory.meta
  |> option.then(fn(meta) { meta.terms_of_service })
  |> option.to_result(Nil)
}

@internal
pub fn acme_error_from_type(
  type_: String,
  detail: String,
  instance: Option(String),
  subproblems: List(Subproblem),
  status: Option(Int),
) -> AcmeError {
  let error_type =
    string.split(type_, ":")
    |> list.last
    |> result.unwrap(type_)

  case error_type {
    "accountDoesNotExist" -> AccountDoesNotExist(detail)
    "alreadyReplaced" -> AlreadyReplaced(detail)
    "alreadyRevoked" -> AlreadyRevoked(detail)
    "badCSR" -> BadCsr(detail)
    "badNonce" -> BadNonce(detail)
    "badPublicKey" -> BadPublicKey(detail)
    "badRevocationReason" -> BadRevocationReason(detail)
    "badSignatureAlgorithm" -> BadSignatureAlgorithm(detail)
    "caa" -> CaaError(detail)
    "compound" -> CompoundError(detail, subproblems)
    "connection" -> ConnectionError(detail)
    "dns" -> DnsError(detail)
    "externalAccountRequired" -> ExternalAccountRequired(detail)
    "incorrectResponse" -> IncorrectResponse(detail)
    "invalidContact" -> InvalidContact(detail)
    "malformed" -> MalformedError(detail)
    "orderNotReady" -> OrderNotReady(detail)
    "rateLimited" -> RateLimited(detail)
    "rejectedIdentifier" -> RejectedIdentifier(detail)
    "serverInternal" -> ServerInternalError(detail)
    "tls" -> TlsError(detail)
    "unauthorized" -> Unauthorized(detail)
    "unsupportedContact" -> UnsupportedContact(detail)
    "unsupportedIdentifier" -> UnsupportedIdentifier(detail)
    "userActionRequired" -> UserActionRequired(detail, instance)
    _ -> UnknownError(type_, detail, status)
  }
}

@internal
pub fn build_fetch(
  url: Url,
  context: Context,
  key: RegisteredKey,
) -> Result(request.Request(String), AcmeError) {
  use body <- result.try(
    jws.sign_with_kid(
      key.jwk,
      kid: key.kid,
      payload: "",
      nonce: context.nonce,
      url: url,
    )
    |> result.map_error(JwsError),
  )

  build_post_request(url, body)
}

@internal
pub fn build_post_request(
  url: Url,
  body: String,
) -> Result(Request(String), AcmeError) {
  utils.request_from_url(url)
  |> request.set_method(http.Post)
  |> request.set_header("content-type", "application/jose+json")
  |> request.set_body(body)
  |> Ok
}

@internal
pub fn identifier_decoder() -> decode.Decoder(Identifier) {
  use type_ <- decode.field("type", decode.string)
  use value <- decode.field("value", decode.string)
  case type_ {
    "dns" -> decode.success(DnsIdentifier(value: value))
    "ip" -> decode.success(IpIdentifier(value: value))
    _ -> decode.failure(DnsIdentifier(value: value), "IdentifierType")
  }
}

@internal
pub fn subproblem_decoder() -> decode.Decoder(Subproblem) {
  use type_ <- decode.field("type", decode.string)
  use detail <- decode.optional_field("detail", "", decode.string)
  use identifier <- decode.optional_field(
    "identifier",
    option.None,
    decode.optional(identifier_decoder()),
  )
  decode.success(Subproblem(type_:, detail:, identifier:))
}
