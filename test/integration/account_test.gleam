import acumen
import acumen/account
import acumen/create_order
import acumen/order
import acumen/register_account
import acumen/rotate_key
import acumen/update_account
import acumen/url
import gleam/string
import gose/jwk
import integration/helpers
import kryptos/ec
import unitest

pub fn registration_creates_account_test() {
  use <- unitest.tag("integration")

  let ctx = helpers.setup_context()
  let unregistered = helpers.generate_key()

  let reg =
    register_account.request()
    |> register_account.contacts(["mailto:test@example.com"])
    |> register_account.agree_to_terms

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: register_account.build(reg, _, unregistered),
      send: helpers.send,
    )

  let assert Ok(#(account, registered_key)) =
    register_account.response(resp, unregistered)

  assert account.status == account.Valid
  assert string.starts_with(
    url.to_string(registered_key.kid),
    helpers.pebble_url,
  )
}

pub fn registration_finds_existing_account_test() {
  use <- unitest.tag("integration")

  let ctx = helpers.setup_context()
  let unregistered = helpers.generate_key()

  let reg =
    register_account.request()
    |> register_account.contacts(["mailto:test@example.com"])
    |> register_account.agree_to_terms

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: register_account.build(reg, _, unregistered),
      send: helpers.send,
    )

  let assert Ok(#(original_account, _)) =
    register_account.response(resp, unregistered)

  let lookup =
    register_account.request()
    |> register_account.only_existing

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: register_account.build(lookup, _, unregistered),
      send: helpers.send,
    )

  let assert Ok(#(found_account, _)) =
    register_account.response(resp, unregistered)

  assert found_account.status == original_account.status
}

pub fn registration_only_existing_fails_for_new_key_test() {
  use <- unitest.tag("integration")

  let ctx = helpers.setup_context()
  let unregistered = helpers.generate_key()

  let reg =
    register_account.request()
    |> register_account.only_existing

  let assert Error(acumen.ProtocolError(
    error: acumen.AccountDoesNotExist(_),
    context: _,
  )) =
    acumen.execute(
      ctx,
      build: register_account.build(reg, _, unregistered),
      send: helpers.send,
    )
}

pub fn updates_account_contacts_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let update =
    update_account.request()
    |> update_account.contacts(["mailto:updated@example.com"])

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: update_account.build(update, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(updated_account) = update_account.response(resp)

  assert updated_account.status == account.Valid
  assert updated_account.contacts == ["mailto:updated@example.com"]
}

pub fn deactivates_account_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let update =
    update_account.request()
    |> update_account.deactivate

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: update_account.build(update, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(deactivated_account) = update_account.response(resp)

  assert deactivated_account.status == account.Deactivated
}

pub fn rotates_account_key_test() {
  use <- unitest.tag("integration")

  let #(_account, old_registered_key, ctx) = helpers.setup_registered_account()

  let new_key = jwk.generate_ec(ec.P256)

  let change = rotate_key.request(new_key)

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: rotate_key.build(change, _, old_registered_key),
      send: helpers.send,
    )

  let assert Ok(new_registered_key) =
    rotate_key.response(resp, new_key, old_registered_key)

  assert new_registered_key.kid == old_registered_key.kid
}

pub fn new_key_works_for_orders_test() {
  use <- unitest.tag("integration")

  let #(_account, old_registered_key, ctx) = helpers.setup_registered_account()

  let new_key = jwk.generate_ec(ec.P256)
  let change = rotate_key.request(new_key)

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: rotate_key.build(change, _, old_registered_key),
      send: helpers.send,
    )

  let assert Ok(new_registered_key) =
    rotate_key.response(resp, new_key, old_registered_key)

  let domain = "keychange-test.example.com"
  let assert Ok(ord) =
    create_order.request(identifiers: [acumen.DnsIdentifier(domain)])

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, new_registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)

  assert created_order.status == order.Pending
}
