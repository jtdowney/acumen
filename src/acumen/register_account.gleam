//// Register a new ACME account.
////
//// Before requesting certificates, you must register an account with the
//// ACME server.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/account.{type Account}
//// import acumen/register_account
//// import gose/key
//// import kryptos/ec
////
//// // Generate an account key (store this securely!)
//// let key = key.generate_ec(ec.P256)
//// let unregistered = acumen.UnregisteredKey(key)
////
//// // Build the registration request
//// let reg = register_account.request()
////   |> register_account.contacts(["mailto:admin@example.com"])
////   |> register_account.agree_to_terms
////
//// // Execute the request
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: register_account.build(reg, _, unregistered),
////   send: httpc.send,
//// )
////
//// // Parse the response to get the account and registered key
//// let assert Ok(#(account, registered_key)) =
////   register_account.response(resp, unregistered)
//// ```

import acumen
import acumen/account.{type Account}
import acumen/internal/jws
import acumen/internal/utils
import acumen/url
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/option.{type Option}
import gleam/result
import gose
import gose/jose/jwk

/// Request builder for account registration.
///
/// Use `request` to create a builder, configure it with `contacts`,
/// `agree_to_terms`, and/or `only_existing`, then call `build`.
pub opaque type RequestBuilder {
  RequestBuilder(
    contacts: List(String),
    terms_of_service_agreed: Bool,
    only_return_existing: Bool,
    external_account_binding: Option(account.ExternalAccountBinding),
  )
}

/// Indicates agreement to the ACME server's terms of service.
///
/// Most ACME servers (including Let's Encrypt) require you to agree to their
/// terms of service. The ToS URL is available in `directory.meta.terms_of_service`.
pub fn agree_to_terms(builder: RequestBuilder) -> RequestBuilder {
  RequestBuilder(..builder, terms_of_service_agreed: True)
}

/// Builds the HTTP request for account registration.
///
/// The full JWK is embedded in the protected header since the key isn't
/// registered yet.
pub fn build(
  builder: RequestBuilder,
  context: acumen.Context,
  key: acumen.UnregisteredKey,
) -> Result(Request(String), acumen.AcmeError) {
  let eab_result = case builder.external_account_binding {
    option.Some(eab) -> build_eab_jws(eab, context.directory.new_account, key)
    option.None -> Ok(option.None)
  }
  use eab_json <- result.try(eab_result)

  build_payload(builder, eab_json)
  |> json.to_string
  |> jws.sign_with_jwk(
    key.jwk,
    payload: _,
    nonce: context.nonce,
    url: context.directory.new_account,
  )
  |> result.map_error(acumen.JwsError)
  |> result.try(acumen.build_post_request(context.directory.new_account, _))
}

fn build_payload(
  builder: RequestBuilder,
  eab_json: Option(json.Json),
) -> json.Json {
  let fields = []

  let fields = case builder.contacts {
    [] -> fields
    contacts -> [#("contact", json.array(contacts, json.string)), ..fields]
  }

  let fields = case builder.terms_of_service_agreed {
    True -> [#("termsOfServiceAgreed", json.bool(True)), ..fields]
    False -> fields
  }

  let fields = case builder.only_return_existing {
    True -> [#("onlyReturnExisting", json.bool(True)), ..fields]
    False -> fields
  }

  let fields = case eab_json {
    option.Some(eab) -> [#("externalAccountBinding", eab), ..fields]
    option.None -> fields
  }

  json.object(fields)
}

fn build_eab_jws(
  eab: account.ExternalAccountBinding,
  url: url.Url,
  key: acumen.UnregisteredKey,
) -> Result(Option(json.Json), acumen.AcmeError) {
  use public_key <- result.try(
    gose.public_key(key.jwk)
    |> result.map_error(fn(e) { acumen.JwsError(utils.gose_error_to_string(e)) }),
  )
  let jwk_json = jwk.to_json(public_key)
  let payload = json.to_string(jwk_json)

  jws.sign_eab(eab.mac_key, kid: eab.key_id, payload:, url:)
  |> result.map(option.Some)
  |> result.map_error(acumen.JwsError)
}

/// Adds contact URLs to the registration request.
///
/// Contact URLs are typically `mailto:` addresses where the CA can reach you
/// about certificate expiration, policy changes, or security issues.
pub fn contacts(
  builder: RequestBuilder,
  contacts: List(String),
) -> RequestBuilder {
  RequestBuilder(..builder, contacts:)
}

/// Adds external account binding credentials to the registration request.
///
/// Some CAs (like Google, ZeroSSL) require you to bind your ACME
/// account to an existing account with them. They provide a key ID and a
/// MAC key (usually base64url-encoded).
///
/// ## Example
///
/// ```gleam
/// let assert Ok(mac_key) = bit_array.base64_url_decode(mac_key_b64)
/// let reg = register_account.request()
///   |> register_account.external_account_binding(key_id: "key-id-from-ca", mac_key: mac_key)
///   |> register_account.agree_to_terms
/// ```
pub fn external_account_binding(
  builder: RequestBuilder,
  key_id key_id: String,
  mac_key mac_key: BitArray,
) -> RequestBuilder {
  RequestBuilder(
    ..builder,
    external_account_binding: option.Some(account.ExternalAccountBinding(
      key_id,
      mac_key,
    )),
  )
}

/// Configures the request to only return an existing account.
///
/// When set, the server will return the existing account for this key if one
/// exists, or return an `AccountDoesNotExist` error if not. No new account
/// will be created.
///
/// This is useful for recovering an account URL when you have the private key
/// but lost the account metadata.
pub fn only_existing(builder: RequestBuilder) -> RequestBuilder {
  RequestBuilder(..builder, only_return_existing: True)
}

/// Creates a new account registration request builder.
///
/// ## Example
///
/// ```gleam
/// let reg = register_account.request()
///   |> register_account.contacts(["mailto:admin@example.com"])
///   |> register_account.agree_to_terms
/// ```
pub fn request() -> RequestBuilder {
  RequestBuilder(
    contacts: [],
    terms_of_service_agreed: False,
    only_return_existing: False,
    external_account_binding: option.None,
  )
}

/// Parses the account registration response.
///
/// Returns the account and a `RegisteredKey` (the key upgraded with the
/// account URL). Use the `RegisteredKey` for all subsequent operations.
pub fn response(
  resp: Response(String),
  key key: acumen.UnregisteredKey,
) -> Result(#(Account, acumen.RegisteredKey), acumen.AcmeError) {
  case resp.status {
    200 | 201 -> parse_account_response(resp, key)
    _ ->
      Error(
        acumen.InvalidResponse(utils.unexpected_status_message(resp.status)),
      )
  }
}

fn parse_account_response(
  resp: Response(String),
  key: acumen.UnregisteredKey,
) -> Result(#(Account, acumen.RegisteredKey), acumen.AcmeError) {
  use location <- result.try(
    response.get_header(resp, "location")
    |> result.replace_error(acumen.InvalidResponse("missing Location header")),
  )
  use kid <- result.try(
    url.from_string(location)
    |> result.replace_error(acumen.InvalidResponse("invalid Location URI")),
  )

  json.parse(resp.body, account.decoder())
  |> result.map_error(fn(error) {
    acumen.JsonParseError(utils.json_parse_error_message("account", error:))
  })
  |> result.map(fn(account) {
    let registered_key = acumen.RegisteredKey(jwk: key.jwk, kid:)
    #(account, registered_key)
  })
}
