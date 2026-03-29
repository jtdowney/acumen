//// Update an existing ACME account.
////
//// After registration, you can update your account by posting to the account
//// URL. Per RFC 8555, you can update:
//// - `contact`: Contact URLs for the account
//// - `termsOfServiceAgreed`: Agreement to terms of service
//// - `status`: Set to "deactivated" to deactivate the account (Section 7.3.6)
////
//// The server ignores updates to `orders` and unrecognized fields.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/update_account
////
//// // Update contact information
//// let update = update_account.request()
////   |> update_account.contacts(["mailto:new-admin@example.com"])
////
//// // Or deactivate the account
//// let deactivate = update_account.request()
////   |> update_account.deactivate
////
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: update_account.build(update, _, registered_key),
////   send: httpc.send,
//// )
////
//// let assert Ok(account) = update_account.response(resp)
//// ```

import acumen
import acumen/account.{type Account}
import acumen/internal/jws
import acumen/internal/utils
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/option.{type Option}
import gleam/result

/// Request builder for account updates.
///
/// Create with `request()`, configure with `contacts()`, `agree_to_terms()`,
/// or `deactivate()`, then pass to `build()`.
pub opaque type RequestBuilder {
  RequestBuilder(
    contacts: Option(List(String)),
    terms_of_service_agreed: Option(Bool),
    deactivate: Bool,
  )
}

/// Indicates agreement to the ACME server's terms of service.
///
/// The ToS URL is available in `directory.meta.terms_of_service`.
pub fn agree_to_terms(builder: RequestBuilder) -> RequestBuilder {
  RequestBuilder(..builder, terms_of_service_agreed: option.Some(True))
}

/// Builds the signed HTTP request for account update.
///
/// Only includes fields that were explicitly set on the builder;
/// omitted fields are left unchanged on the server.
pub fn build(
  builder: RequestBuilder,
  context: acumen.Context,
  key: acumen.RegisteredKey,
) -> Result(Request(String), acumen.AcmeError) {
  build_payload(builder)
  |> json.to_string
  |> jws.sign_with_kid(
    key.jwk,
    kid: key.kid,
    payload: _,
    nonce: context.nonce,
    url: key.kid,
  )
  |> result.map_error(acumen.JwsError)
  |> result.try(acumen.build_post_request(key.kid, _))
}

fn build_payload(builder: RequestBuilder) -> json.Json {
  let fields = []

  let fields = case builder.contacts {
    option.Some(contacts) -> [
      #("contact", json.array(contacts, json.string)),
      ..fields
    ]
    option.None -> fields
  }

  let fields = case builder.terms_of_service_agreed {
    option.Some(agreed) -> [
      #("termsOfServiceAgreed", json.bool(agreed)),
      ..fields
    ]
    option.None -> fields
  }

  let fields = case builder.deactivate {
    True -> [#("status", json.string("deactivated")), ..fields]
    False -> fields
  }

  json.object(fields)
}

/// Sets the new contact URLs for the account.
///
/// Contact URLs are typically `mailto:` addresses where the CA can reach you
/// about certificate expiration, policy changes, or security issues.
pub fn contacts(
  builder: RequestBuilder,
  contacts: List(String),
) -> RequestBuilder {
  RequestBuilder(..builder, contacts: option.Some(contacts))
}

/// Marks the account for deactivation.
///
/// Once deactivated, the account cannot be used for any further operations.
/// This action is permanent.
pub fn deactivate(builder: RequestBuilder) -> RequestBuilder {
  RequestBuilder(..builder, deactivate: True)
}

/// Creates a new account update request builder with no changes set.
///
/// ## Example
///
/// ```gleam
/// let update = update_account.request()
///   |> update_account.contacts(["mailto:new@example.com"])
/// ```
pub fn request() -> RequestBuilder {
  RequestBuilder(
    contacts: option.None,
    terms_of_service_agreed: option.None,
    deactivate: False,
  )
}

/// Parses the account update response.
///
/// Returns the full account state after the update, including any
/// fields that were not modified.
pub fn response(resp: Response(String)) -> Result(Account, acumen.AcmeError) {
  case resp.status {
    200 ->
      json.parse(resp.body, account.decoder())
      |> result.map_error(fn(error) {
        acumen.JsonParseError(utils.json_parse_error_message("account", error:))
      })
    _ ->
      Error(
        acumen.InvalidResponse(utils.unexpected_status_message(resp.status)),
      )
  }
}
