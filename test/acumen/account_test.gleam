import acumen/account
import acumen/url
import gleam/json
import gleam/option

pub fn decoder_full_fields_test() {
  let body =
    json.object([
      #("status", json.string("valid")),
      #("contact", json.array(["mailto:admin@example.com"], json.string)),
      #("orders", json.string("https://example.com/orders")),
      #("termsOfServiceAgreed", json.bool(True)),
    ])
    |> json.to_string

  let assert Ok(acct) = json.parse(body, account.decoder())

  assert acct.status == account.Valid
  assert acct.contacts == ["mailto:admin@example.com"]
  let assert Ok(expected_orders_url) =
    url.from_string("https://example.com/orders")
  assert acct.orders_url == option.Some(expected_orders_url)
  assert acct.terms_of_service_agreed == option.Some(True)
}

pub fn decoder_revoked_status_test() {
  let body =
    json.object([#("status", json.string("revoked"))])
    |> json.to_string

  let assert Ok(acct) = json.parse(body, account.decoder())

  assert acct.status == account.Revoked
}

pub fn decoder_minimal_fields_test() {
  let body =
    json.object([#("status", json.string("deactivated"))])
    |> json.to_string

  let assert Ok(acct) = json.parse(body, account.decoder())

  assert acct.status == account.Deactivated
  assert acct.contacts == []
  assert acct.orders_url == option.None
  assert acct.terms_of_service_agreed == option.None
}
