import acumen
import acumen/authorization
import acumen/challenge
import acumen/create_order
import acumen/deactivate_authorization
import acumen/fetch_authorization
import acumen/order
import acumen/validate_challenge
import integration/helpers
import unitest

pub fn fetches_authorization_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let assert Ok(ord) =
    create_order.request(identifiers: [
      acumen.DnsIdentifier("authz-fetch.example.com"),
    ])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)
  let assert [auth_url, ..] = created_order.authorizations
  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: acumen.build_fetch(auth_url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(auth) = fetch_authorization.response(resp, auth_url)

  assert auth.status == authorization.Pending
  assert auth.identifier == acumen.DnsIdentifier("authz-fetch.example.com")
  assert auth.challenges != []
}

pub fn completes_http01_challenge_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let domain = "challenge-test.example.com"
  let #(ready_order, _ctx) =
    helpers.complete_http01_order(ctx, registered_key, domain)

  assert ready_order.status == order.Ready
}

pub fn completes_dns01_challenge_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let domain = "dns01-test.example.com"
  let assert Ok(ord) =
    create_order.request(identifiers: [acumen.DnsIdentifier(domain)])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)
  let assert [auth_url, ..] = created_order.authorizations

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: acumen.build_fetch(auth_url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(auth) = fetch_authorization.response(resp, auth_url)
  let assert Ok(dns_challenge) =
    challenge.find_by_type(auth.challenges, of: challenge.Dns01)

  let assert Ok(key_auth) =
    challenge.key_authorization(dns_challenge, registered_key)
  let assert Ok(txt_value) = challenge.dns01_txt_record(key_auth)
  helpers.add_dns01_challenge(domain, txt_value)

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: validate_challenge.build(dns_challenge.url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(_updated_challenge) = validate_challenge.response(resp)

  let #(ready_order, _ctx) =
    helpers.poll_order_until_ready(ctx, created_order, registered_key)

  assert ready_order.status == order.Ready
}

pub fn validate_challenge_returns_updated_challenge_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let domain = "validate-challenge.example.com"
  let assert Ok(ord) =
    create_order.request(identifiers: [acumen.DnsIdentifier(domain)])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)
  let assert [auth_url, ..] = created_order.authorizations

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: acumen.build_fetch(auth_url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(auth) = fetch_authorization.response(resp, auth_url)
  let assert Ok(http_challenge) =
    challenge.find_by_type(auth.challenges, of: challenge.Http01)
  let assert Ok(token) = challenge.token(http_challenge)

  let assert Ok(key_auth) =
    challenge.key_authorization(http_challenge, registered_key)
  helpers.add_http01_challenge(token, key_auth)

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: validate_challenge.build(http_challenge.url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(updated_challenge) = validate_challenge.response(resp)

  assert challenge.url(updated_challenge) == challenge.url(http_challenge)
  let status = challenge.status(updated_challenge)
  assert status == challenge.Processing || status == challenge.Valid
}

pub fn deactivates_pending_authorization_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let domain = "deactivate-authz.example.com"
  let assert Ok(ord) =
    create_order.request(identifiers: [acumen.DnsIdentifier(domain)])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)
  let assert [auth_url, ..] = created_order.authorizations

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: acumen.build_fetch(auth_url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(auth) = fetch_authorization.response(resp, auth_url)
  assert auth.status == authorization.Pending

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: deactivate_authorization.build(auth_url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(deactivated_auth) =
    deactivate_authorization.response(resp, auth_url)

  assert deactivated_auth.status == authorization.Deactivated
  assert deactivated_auth.identifier == acumen.DnsIdentifier(domain)
}
