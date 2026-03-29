import acumen
import acumen/account
import acumen/register_account
import acumen/url
import birdie
import gleam/bit_array
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/json
import gleam/option
import support/fixtures

pub fn build_creates_post_to_new_account_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_unregistered_key()
  let builder = register_account.request()

  let assert Ok(req) = register_account.build(builder, ctx, key)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/endpoint"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn build_base_payload_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_unregistered_key()
  let builder = register_account.request()

  let assert Ok(req) = register_account.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  assert payload == "{}"
}

pub fn build_with_contacts_payload_snapshot_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_unregistered_key()
  let builder =
    register_account.request()
    |> register_account.contacts(["mailto:admin@example.com"])

  let assert Ok(req) = register_account.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "register account with contacts payload")
}

pub fn build_with_agree_to_terms_payload_snapshot_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_unregistered_key()
  let builder =
    register_account.request()
    |> register_account.agree_to_terms

  let assert Ok(req) = register_account.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "register account with agree to terms payload")
}

pub fn build_with_only_existing_payload_snapshot_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_unregistered_key()
  let builder =
    register_account.request()
    |> register_account.only_existing

  let assert Ok(req) = register_account.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "register account with only existing payload")
}

pub fn response_parses_account_with_all_fields_test() {
  let key = fixtures.test_unregistered_key()
  let body =
    json.object([
      #("status", json.string("valid")),
      #("contact", json.array(["mailto:admin@example.com"], json.string)),
      #("orders", json.string("https://example.com/orders")),
      #("termsOfServiceAgreed", json.bool(True)),
    ])
    |> json.to_string
  let resp =
    fixtures.acme_response(
      200,
      "new-nonce",
      "https://example.com/acct/123",
      body,
    )

  let assert Ok(#(account, registered_key)) =
    register_account.response(resp, key)

  assert account.status == account.Valid
  assert account.contacts == ["mailto:admin@example.com"]
  let assert Ok(expected_orders_url) =
    url.from_string("https://example.com/orders")
  assert account.orders_url == option.Some(expected_orders_url)
  assert account.terms_of_service_agreed == option.Some(True)
  let assert Ok(expected_kid) = url.from_string("https://example.com/acct/123")
  assert registered_key.kid == expected_kid
}

pub fn response_uses_defaults_for_optional_fields_test() {
  let key = fixtures.test_unregistered_key()
  let body = json.object([#("status", json.string("valid"))]) |> json.to_string
  let resp =
    fixtures.acme_response(
      200,
      "new-nonce",
      "https://example.com/acct/123",
      body,
    )

  let assert Ok(#(account, _)) = register_account.response(resp, key)

  assert account.contacts == []
  assert account.orders_url == option.None
  assert account.terms_of_service_agreed == option.None
}

pub fn response_parses_account_with_201_status_test() {
  let key = fixtures.test_unregistered_key()
  let body = json.object([#("status", json.string("valid"))]) |> json.to_string
  let resp =
    fixtures.acme_response(
      201,
      "new-nonce",
      "https://example.com/acct/123",
      body,
    )

  let assert Ok(#(account, registered_key)) =
    register_account.response(resp, key)

  assert account.status == account.Valid
  let assert Ok(expected_kid) = url.from_string("https://example.com/acct/123")
  assert registered_key.kid == expected_kid
}

pub fn response_rejects_unexpected_status_test() {
  let key = fixtures.test_unregistered_key()
  let resp =
    fixtures.acme_response(
      400,
      "new-nonce",
      "https://example.com/acct/123",
      "{}",
    )

  let assert Error(acumen.InvalidResponse(_)) =
    register_account.response(resp, key)
}

pub fn response_rejects_missing_location_header_test() {
  let key = fixtures.test_unregistered_key()
  let body = json.object([#("status", json.string("valid"))]) |> json.to_string
  let resp = fixtures.nonce_response(201, "new-nonce", body)

  let assert Error(acumen.InvalidResponse(_)) =
    register_account.response(resp, key)
}

pub fn response_rejects_relative_location_uri_test() {
  let key = fixtures.test_unregistered_key()
  let body = json.object([#("status", json.string("valid"))]) |> json.to_string
  let resp = fixtures.acme_response(200, "new-nonce", "/acct/123", body)

  let assert Error(acumen.InvalidResponse(msg)) =
    register_account.response(resp, key)
  assert msg == "invalid Location URI"
}

pub fn response_rejects_malformed_json_body_test() {
  let key = fixtures.test_unregistered_key()
  let resp =
    fixtures.acme_response(
      201,
      "new-nonce",
      "https://example.com/acct/123",
      "not json",
    )

  let assert Error(acumen.JsonParseError(_)) =
    register_account.response(resp, key)
}

pub fn external_account_binding_creates_valid_jws_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_unregistered_key()
  let mac_key = <<
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
  >>
  let builder =
    register_account.request()
    |> register_account.external_account_binding("eab-kid-123", mac_key)

  let assert Ok(req) = register_account.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)

  let eab_decoder = {
    use protected <- decode.field("protected", decode.string)
    use signature <- decode.field("signature", decode.string)
    decode.success(#(protected, signature))
  }
  let outer_decoder = {
    use eab <- decode.field("externalAccountBinding", eab_decoder)
    decode.success(eab)
  }
  let assert Ok(#(protected_b64, signature)) =
    json.parse(payload, outer_decoder)

  assert signature != ""

  let assert Ok(protected_bytes) = bit_array.base64_url_decode(protected_b64)
  let assert Ok(protected) = bit_array.to_string(protected_bytes)

  let header_decoder = {
    use alg <- decode.field("alg", decode.string)
    use kid <- decode.field("kid", decode.string)
    use url <- decode.field("url", decode.string)
    decode.success(#(alg, kid, url))
  }
  let assert Ok(#(alg, kid, url)) = json.parse(protected, header_decoder)
  assert alg == "HS256"
  assert kid == "eab-kid-123"
  assert url == "https://example.com/endpoint"
}
