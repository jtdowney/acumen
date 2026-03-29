import acumen
import acumen/account
import acumen/update_account
import birdie
import gleam/http
import gleam/http/request
import gleam/json
import support/fixtures

pub fn build_creates_post_to_account_url_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let builder =
    update_account.request()
    |> update_account.contacts(["mailto:new-admin@example.com"])

  let assert Ok(req) = update_account.build(builder, ctx, key)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/acct/123"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn build_contacts_payload_snapshot_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let builder =
    update_account.request()
    |> update_account.contacts(["mailto:new-admin@example.com"])

  let assert Ok(req) = update_account.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "update account contacts payload")
}

pub fn build_agree_to_terms_payload_snapshot_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let builder =
    update_account.request()
    |> update_account.agree_to_terms

  let assert Ok(req) = update_account.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "update account agree to terms payload")
}

pub fn build_deactivate_payload_snapshot_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let builder =
    update_account.request()
    |> update_account.deactivate

  let assert Ok(req) = update_account.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  birdie.snap(payload, "update account deactivate payload")
}

pub fn build_empty_request_produces_empty_payload_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let builder = update_account.request()

  let assert Ok(req) = update_account.build(builder, ctx, key)

  let assert Ok(payload) = fixtures.extract_jws_payload(req.body)
  assert payload == "{}"
}

pub fn response_parses_updated_account_test() {
  let body =
    json.object([
      #("status", json.string("valid")),
      #("contact", json.array(["mailto:new-admin@example.com"], json.string)),
    ])
    |> json.to_string
  let resp =
    fixtures.acme_response(
      200,
      "new-nonce",
      "https://example.com/acct/123",
      body,
    )

  let assert Ok(acct) = update_account.response(resp)

  assert acct.status == account.Valid
  assert acct.contacts == ["mailto:new-admin@example.com"]
}

pub fn response_parses_deactivated_account_test() {
  let body =
    json.object([
      #("status", json.string("deactivated")),
      #("contact", json.array(["mailto:test@example.com"], json.string)),
    ])
    |> json.to_string

  let resp =
    fixtures.acme_response(
      200,
      "new-nonce",
      "https://example.com/acct/123",
      body,
    )

  let assert Ok(acct) = update_account.response(resp)

  assert acct.status == account.Deactivated
}

pub fn response_rejects_unexpected_status_test() {
  let resp =
    fixtures.acme_response(
      403,
      "new-nonce",
      "https://example.com/acct/123",
      "{}",
    )

  let assert Error(acumen.InvalidResponse(_)) = update_account.response(resp)
}

pub fn response_rejects_malformed_json_body_test() {
  let resp =
    fixtures.acme_response(
      200,
      "new-nonce",
      "https://example.com/acct/123",
      "not json",
    )

  let assert Error(acumen.JsonParseError(_)) = update_account.response(resp)
}
