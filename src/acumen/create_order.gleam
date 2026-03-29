//// Create a new ACME order for certificate issuance.
////
//// Before obtaining a certificate, you must create an order specifying which
//// identifiers (domain names or IP addresses) you want on the certificate.
////
//// ## Example
////
//// ```gleam
//// import acumen
//// import acumen/create_order
//// import acumen/order.{type Order}
////
//// let assert Ok(ord) = create_order.request(identifiers: [
////   acumen.DnsIdentifier("example.com"),
////   acumen.DnsIdentifier("www.example.com"),
//// ])
////
//// let assert Ok(#(resp, ctx)) = acumen.execute(
////   ctx,
////   build: create_order.build(ord, _, registered_key),
////   send: httpc.send,
//// )
////
//// let assert Ok(created_order) = create_order.response(resp)
//// ```

import acumen
import acumen/internal/jws
import acumen/internal/utils
import acumen/order.{type Order}
import acumen/url
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/option.{type Option}
import gleam/result
import gleam/time/duration
import gleam/time/timestamp.{type Timestamp}

/// Request builder for order creation.
///
/// Use `request` to create a builder with required identifiers, optionally
/// configure it with `not_before`, `not_after`, `replaces`, and `profile`,
/// then call `build`.
pub opaque type RequestBuilder {
  RequestBuilder(
    identifiers: List(acumen.Identifier),
    not_before: Option(Timestamp),
    not_after: Option(Timestamp),
    profile: Option(String),
    replaces: Option(String),
  )
}

/// Builds the signed HTTP request for order creation.
///
/// Sends the identifiers and any optional constraints (profile,
/// notBefore/notAfter, replaces) to the ACME server's `newOrder` endpoint.
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
    url: context.directory.new_order,
  )
  |> result.map_error(acumen.JwsError)
  |> result.try(acumen.build_post_request(context.directory.new_order, _))
}

fn build_payload(builder: RequestBuilder) -> json.Json {
  let utc = duration.seconds(0)
  let timestamp_field = fn(ts) { json.string(timestamp.to_rfc3339(ts, utc)) }

  [
    #("identifiers", json.array(builder.identifiers, identifier_to_json)),
    ..option.values([
      option.map(builder.not_before, fn(v) {
        #("notBefore", timestamp_field(v))
      }),
      option.map(builder.not_after, fn(v) { #("notAfter", timestamp_field(v)) }),
      option.map(builder.profile, fn(v) { #("profile", json.string(v)) }),
      option.map(builder.replaces, fn(v) { #("replaces", json.string(v)) }),
    ])
  ]
  |> json.object
}

fn identifier_to_json(identifier: acumen.Identifier) -> json.Json {
  case identifier {
    acumen.DnsIdentifier(value) ->
      json.object([
        #("type", json.string("dns")),
        #("value", json.string(value)),
      ])
    acumen.IpIdentifier(value) ->
      json.object([#("type", json.string("ip")), #("value", json.string(value))])
  }
}

/// Sets the requested notAfter constraint on the certificate.
///
/// The CA may ignore this or apply its own constraints.
pub fn not_after(
  builder: RequestBuilder,
  timestamp: Timestamp,
) -> RequestBuilder {
  RequestBuilder(..builder, not_after: option.Some(timestamp))
}

/// Sets the requested notBefore constraint on the certificate.
///
/// The CA may ignore this or apply its own constraints.
pub fn not_before(
  builder: RequestBuilder,
  timestamp: Timestamp,
) -> RequestBuilder {
  RequestBuilder(..builder, not_before: option.Some(timestamp))
}

/// Sets the certificate issuance profile for the order.
///
/// Available profiles can be discovered with `acumen.profiles(directory)`.
pub fn profile(builder: RequestBuilder, name: String) -> RequestBuilder {
  RequestBuilder(..builder, profile: option.Some(name))
}

/// Sets the certificate being replaced.
///
/// Build `cert_id` with `renewal_info.cert_id` or
/// `renewal_info.cert_id_from_certificate`.
pub fn replaces(builder: RequestBuilder, cert_id: String) -> RequestBuilder {
  RequestBuilder(..builder, replaces: option.Some(cert_id))
}

/// Creates a new order request builder. At least one identifier is required.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(ord) = create_order.request(identifiers: [
///   acumen.DnsIdentifier("example.com"),
///   acumen.DnsIdentifier("www.example.com"),
/// ])
/// ```
pub fn request(
  identifiers identifiers: List(acumen.Identifier),
) -> Result(RequestBuilder, acumen.AcmeError) {
  case identifiers {
    [] -> Error(acumen.InvalidRequest("identifiers list cannot be empty"))
    _ ->
      Ok(RequestBuilder(
        identifiers:,
        not_before: option.None,
        not_after: option.None,
        profile: option.None,
        replaces: option.None,
      ))
  }
}

/// Parses the order creation response.
///
/// Accepts both 200 and 201 status codes — the server may return an
/// existing order for duplicate identifiers.
pub fn response(resp: Response(String)) -> Result(Order, acumen.AcmeError) {
  case resp.status {
    200 | 201 -> parse_order_creation_response(resp)
    _ ->
      Error(
        acumen.InvalidResponse(utils.unexpected_status_message(resp.status)),
      )
  }
}

fn parse_order_creation_response(
  resp: Response(String),
) -> Result(Order, acumen.AcmeError) {
  use location <- result.try(
    response.get_header(resp, "location")
    |> result.replace_error(acumen.InvalidResponse("missing Location header")),
  )
  url.from_string(location)
  |> result.replace_error(acumen.InvalidResponse("invalid Location URI"))
  |> result.try(order.parse_order_response(resp, _))
}
