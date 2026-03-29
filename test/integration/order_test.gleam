import acumen
import acumen/create_order
import acumen/fetch_order
import acumen/list_orders
import acumen/order
import acumen/url
import gleam/list
import gleam/option
import gleam/string
import integration/helpers
import unitest

pub fn creates_pending_order_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let assert Ok(ord) =
    create_order.request(identifiers: [acumen.DnsIdentifier("example.com")])

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)

  assert created_order.status == order.Pending
  assert created_order.identifiers == [acumen.DnsIdentifier("example.com")]
  assert string.starts_with(
    url.to_string(created_order.finalize_url),
    helpers.pebble_url,
  )
}

pub fn creates_order_with_multiple_domains_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let assert Ok(ord) =
    create_order.request(identifiers: [
      acumen.DnsIdentifier("example.com"),
      acumen.DnsIdentifier("www.example.com"),
      acumen.DnsIdentifier("mail.example.com"),
    ])

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)

  assert created_order.status == order.Pending
  assert list.length(created_order.identifiers) == 3
}

pub fn has_authorization_urls_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let assert Ok(ord) =
    create_order.request(identifiers: [
      acumen.DnsIdentifier("authz-test.example.com"),
    ])

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)

  assert list.length(created_order.authorizations) == 1

  let assert [authz_url] = created_order.authorizations
  assert string.starts_with(url.to_string(authz_url), helpers.pebble_url)
}

pub fn order_returns_default_profile_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let assert Ok(ord) =
    create_order.request(identifiers: [
      acumen.DnsIdentifier("profile-test.example.com"),
    ])

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)

  let assert option.Some(_profile) = created_order.profile
}

pub fn order_with_explicit_profile_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let assert Ok(ord) =
    create_order.request(identifiers: [
      acumen.DnsIdentifier("explicit-profile.example.com"),
    ])
  let ord = create_order.profile(ord, "default")

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)

  assert created_order.profile == option.Some("default")
}

pub fn retrieves_existing_order_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let assert Ok(ord) =
    create_order.request(identifiers: [
      acumen.DnsIdentifier("fetch-test.example.com"),
    ])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: acumen.build_fetch(created_order.url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(fetched_order) = fetch_order.response(resp, created_order.url)

  assert fetched_order.url == created_order.url
  assert fetched_order.status == created_order.status
  assert fetched_order.identifiers == created_order.identifiers
}

pub fn lists_orders_for_account_test() {
  use <- unitest.tag("integration")

  let #(account, registered_key, ctx) = helpers.setup_registered_account()

  let assert Ok(ord) =
    create_order.request(identifiers: [
      acumen.DnsIdentifier("list-orders-1.example.com"),
    ])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(_created_order) = create_order.response(resp)

  let assert option.Some(orders_url) = account.orders_url

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: list_orders.build(orders_url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(orders_list) = list_orders.response(resp)

  assert list.length(orders_list.orders) >= 1
}

pub fn lists_multiple_orders_test() {
  use <- unitest.tag("integration")

  let #(account, registered_key, ctx) = helpers.setup_registered_account()

  let assert Ok(ord1) =
    create_order.request(identifiers: [
      acumen.DnsIdentifier("list-multi-1.example.com"),
    ])
  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord1, _, registered_key),
      send: helpers.send,
    )
  let assert Ok(_order1) = create_order.response(resp)

  let assert Ok(ord2) =
    create_order.request(identifiers: [
      acumen.DnsIdentifier("list-multi-2.example.com"),
    ])
  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord2, _, registered_key),
      send: helpers.send,
    )
  let assert Ok(_order2) = create_order.response(resp)

  let assert option.Some(orders_url) = account.orders_url

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: list_orders.build(orders_url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(orders_list) = list_orders.response(resp)

  assert list.length(orders_list.orders) >= 2
}
