import acumen
import acumen/create_order
import acumen/order
import acumen/url
import birdie
import gleam/http
import gleam/http/request
import gleam/json
import gleam/option
import gleam/time/timestamp
import support/fixtures

pub fn build_creates_post_to_new_order_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(builder) =
    create_order.request(identifiers: [acumen.DnsIdentifier("example.com")])

  let assert Ok(req) = create_order.build(builder, ctx, key)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/endpoint"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn response_parses_order_with_all_fields_test() {
  let body =
    json.object([
      #("status", json.string("pending")),
      #(
        "identifiers",
        json.preprocessed_array([
          json.object([
            #("type", json.string("dns")),
            #("value", json.string("example.com")),
          ]),
        ]),
      ),
      #(
        "authorizations",
        json.array(["https://example.com/authz/1"], json.string),
      ),
      #("finalize", json.string("https://example.com/finalize/1")),
      #("certificate", json.string("https://example.com/cert/1")),
      #("expires", json.string("2024-12-31T23:59:59Z")),
      #("notBefore", json.string("2024-01-01T00:00:00Z")),
      #("notAfter", json.string("2024-06-30T23:59:59Z")),
      #("profile", json.string("tlsserver")),
    ])
    |> json.to_string
  let resp =
    fixtures.acme_response(
      201,
      "new-nonce",
      "https://example.com/order/123",
      body,
    )

  let assert Ok(ord) = create_order.response(resp)
  let assert Ok(expected_url) = url.from_string("https://example.com/order/123")

  assert ord.url == expected_url
  assert ord.status == order.Pending
  assert ord.identifiers == [acumen.DnsIdentifier("example.com")]
  let assert Ok(expected_expires) =
    timestamp.parse_rfc3339("2024-12-31T23:59:59Z")
  let assert Ok(expected_not_before) =
    timestamp.parse_rfc3339("2024-01-01T00:00:00Z")
  let assert Ok(expected_not_after) =
    timestamp.parse_rfc3339("2024-06-30T23:59:59Z")
  assert ord.expires == option.Some(expected_expires)
  assert ord.not_before == option.Some(expected_not_before)
  assert ord.not_after == option.Some(expected_not_after)
  assert ord.profile == option.Some("tlsserver")
}

pub fn response_parses_minimal_order_test() {
  let body =
    json.object(fixtures.minimal_order_fields(["example.com"]))
    |> json.to_string
  let resp =
    fixtures.acme_response(
      201,
      "new-nonce",
      "https://example.com/order/123",
      body,
    )

  let assert Ok(ord) = create_order.response(resp)

  assert ord.status == order.Pending
  assert ord.identifiers == [acumen.DnsIdentifier("example.com")]
  assert ord.expires == option.None
  assert ord.profile == option.None
}

pub fn build_single_identifier_payload_snapshot_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(builder) =
    create_order.request(identifiers: [acumen.DnsIdentifier("example.com")])

  let assert Ok(req) = create_order.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "create order single identifier payload")
}

pub fn build_with_multiple_identifiers_payload_snapshot_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(builder) =
    create_order.request(identifiers: [
      acumen.DnsIdentifier("example.com"),
      acumen.DnsIdentifier("www.example.com"),
      acumen.IpIdentifier("192.0.2.1"),
    ])

  let assert Ok(req) = create_order.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "create order multiple identifiers payload")
}

pub fn build_with_optional_fields_payload_snapshot_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(not_before) = timestamp.parse_rfc3339("2024-01-01T00:00:00Z")
  let assert Ok(not_after) = timestamp.parse_rfc3339("2024-12-31T23:59:59Z")
  let assert Ok(builder) =
    create_order.request(identifiers: [acumen.DnsIdentifier("example.com")])
  let builder =
    builder
    |> create_order.not_before(not_before)
    |> create_order.not_after(not_after)
    |> create_order.profile("tlsserver")

  let assert Ok(req) = create_order.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "create order with optional fields payload")
}

pub fn build_with_replaces_payload_snapshot_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(builder) =
    create_order.request(identifiers: [acumen.DnsIdentifier("example.com")])
  let builder =
    builder
    |> create_order.replaces("aYhba4dGQEHPTBhac0U2nY0.AAABkNRR7v4")

  let assert Ok(req) = create_order.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "create order with replaces payload")
}

pub fn response_parses_ip_identifiers_test() {
  let body =
    json.object([
      #("status", json.string("pending")),
      #(
        "identifiers",
        json.preprocessed_array([
          json.object([
            #("type", json.string("ip")),
            #("value", json.string("192.0.2.1")),
          ]),
        ]),
      ),
      #(
        "authorizations",
        json.array(["https://example.com/authz/1"], json.string),
      ),
      #("finalize", json.string("https://example.com/finalize/1")),
    ])
    |> json.to_string
  let resp =
    fixtures.acme_response(
      201,
      "new-nonce",
      "https://example.com/order/123",
      body,
    )

  let assert Ok(ord) = create_order.response(resp)
  assert ord.identifiers == [acumen.IpIdentifier("192.0.2.1")]
}

pub fn response_accepts_status_200_test() {
  let body =
    json.object(fixtures.minimal_order_fields(["example.com"]))
    |> json.to_string
  let resp =
    fixtures.acme_response(
      200,
      "new-nonce",
      "https://example.com/order/123",
      body,
    )

  let assert Ok(ord) = create_order.response(resp)
  assert ord.identifiers == [acumen.DnsIdentifier("example.com")]
}

pub fn response_rejects_unexpected_status_test() {
  let resp =
    fixtures.acme_response(
      400,
      "new-nonce",
      "https://example.com/order/123",
      "{}",
    )

  let assert Error(acumen.InvalidResponse(_)) = create_order.response(resp)
}

pub fn response_rejects_missing_location_header_test() {
  let body =
    json.object(fixtures.minimal_order_fields(["example.com"]))
    |> json.to_string
  let resp = fixtures.nonce_response(201, "new-nonce", body)

  let assert Error(acumen.InvalidResponse(_)) = create_order.response(resp)
}

pub fn response_rejects_malformed_json_body_test() {
  let resp =
    fixtures.acme_response(
      201,
      "new-nonce",
      "https://example.com/order/123",
      "not json",
    )

  let assert Error(acumen.JsonParseError(_)) = create_order.response(resp)
}

pub fn request_rejects_empty_identifiers_test() {
  let assert Error(acumen.InvalidRequest(_)) =
    create_order.request(identifiers: [])
}
