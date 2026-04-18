import acumen
import acumen/create_order
import acumen/fetch_certificate
import acumen/fetch_renewal_info
import acumen/finalize_order
import acumen/order
import acumen/renewal_info
import acumen/revoke_certificate
import gleam/bit_array
import gleam/order as ord
import gleam/result
import gleam/string
import gleam/time/timestamp
import gose/jose/jwk
import integration/helpers
import kryptos/x509/certificate
import unitest

pub fn finalizes_order_with_csr_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let domain = "finalize-test.example.com"
  let #(ready_order, ctx) =
    helpers.complete_http01_order(ctx, registered_key, domain)

  let csr = helpers.generate_csr([domain])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: finalize_order.build(
        ready_order.finalize_url,
        _,
        registered_key,
        csr:,
      ),
      send: helpers.send,
    )

  let assert Ok(finalized) = finalize_order.response(resp, ready_order.url)

  assert is_processing_or_valid(finalized.status)
  assert finalized.identifiers == [acumen.DnsIdentifier(domain)]

  // Poll until certificate is ready
  let #(valid_order, ctx) =
    helpers.poll_order_until_valid(ctx, ready_order, registered_key)

  let assert order.Valid(cert_url) = valid_order.status

  let assert Ok(#(cert_resp, _ctx)) =
    acumen.execute(
      ctx,
      build: fetch_certificate.build(cert_url, _, registered_key),
      send: helpers.send,
    )
  let assert Ok(pem_chain) = fetch_certificate.response(cert_resp)
  assert string.starts_with(pem_chain, "-----BEGIN CERTIFICATE-----")
}

pub fn finalize_before_ready_returns_error_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let domain = "not-ready-test.example.com"
  let assert Ok(ord) =
    create_order.request(identifiers: [acumen.DnsIdentifier(domain)])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: create_order.build(ord, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(created_order) = create_order.response(resp)

  let csr = helpers.generate_csr([domain])

  let assert Error(acumen.ProtocolError(error: acumen.OrderNotReady(_), ..)) =
    acumen.execute(
      ctx,
      build: finalize_order.build(
        created_order.finalize_url,
        _,
        registered_key,
        csr:,
      ),
      send: helpers.send,
    )
}

pub fn revokes_certificate_test() {
  use <- unitest.tag("integration")

  let #(cert_der, registered_key, ctx) =
    issue_certificate("revoke-test.example.com")

  let rev =
    revoke_certificate.request(cert_der)
    |> revoke_certificate.reason(revoke_certificate.Superseded)

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: revoke_certificate.build(rev, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(Nil) = revoke_certificate.response(resp)
}

pub fn double_revocation_returns_error_test() {
  use <- unitest.tag("integration")

  let #(cert_der, registered_key, ctx) =
    issue_certificate("double-revoke.example.com")

  let rev = revoke_certificate.request(cert_der)

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: revoke_certificate.build(rev, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(Nil) = revoke_certificate.response(resp)

  let rev2 = revoke_certificate.request(cert_der)

  let assert Error(acumen.ProtocolError(error: acumen.AlreadyRevoked(_), ..)) =
    acumen.execute(
      ctx,
      build: revoke_certificate.build(rev2, _, registered_key),
      send: helpers.send,
    )
}

pub fn revokes_certificate_with_certificate_key_test() {
  use <- unitest.tag("integration")

  let #(cert_der, cert_jwk, _registered_key, ctx) =
    issue_certificate_with_key("revoke-cert-key.example.com")

  let req =
    revoke_certificate.request(cert_der)
    |> revoke_certificate.reason(revoke_certificate.KeyCompromise)

  let assert Ok(#(resp, _ctx)) =
    acumen.execute(
      ctx,
      build: revoke_certificate.build_with_certificate_key(req, _, cert_jwk),
      send: helpers.send,
    )

  let assert Ok(Nil) = revoke_certificate.response(resp)
}

pub fn fetches_renewal_info_for_issued_certificate_test() {
  use <- unitest.tag("integration")

  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let domain = "renewal-info-test.example.com"
  let #(ready_order, ctx) =
    helpers.complete_http01_order(ctx, registered_key, domain)

  let csr = helpers.generate_csr([domain])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: finalize_order.build(
        ready_order.finalize_url,
        _,
        registered_key,
        csr:,
      ),
      send: helpers.send,
    )

  let assert Ok(_finalized) = finalize_order.response(resp, ready_order.url)

  let #(valid_order, ctx) =
    helpers.poll_order_until_valid(ctx, ready_order, registered_key)

  let assert order.Valid(cert_url) = valid_order.status

  let assert Ok(#(cert_resp, _ctx)) =
    acumen.execute(
      ctx,
      build: fetch_certificate.build(cert_url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(pem_chain) = fetch_certificate.response(cert_resp)
  assert string.starts_with(pem_chain, "-----BEGIN CERTIFICATE-----")

  let assert Ok(certs) = certificate.from_pem(pem_chain)
  let assert [cert, ..] = certs
  let assert Ok(cert_id) = renewal_info.cert_id_from_certificate(cert)

  let assert Ok(req) = fetch_renewal_info.build(ctx.directory, cert_id)
  let assert Ok(resp) = helpers.send(req)
  let assert Ok(info) = fetch_renewal_info.response(resp)

  assert timestamp.compare(info.suggested_window.start, timestamp.system_time())
    != ord.Lt
  assert timestamp.compare(
      info.suggested_window.end,
      info.suggested_window.start,
    )
    != ord.Lt
}

fn is_processing_or_valid(status: order.Status) -> Bool {
  case status {
    order.Processing | order.Valid(_) -> True
    order.Pending | order.Ready | order.Invalid -> False
  }
}

fn issue_certificate_with_key(
  domain: String,
) -> #(BitArray, jwk.Key, acumen.RegisteredKey, acumen.Context) {
  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let #(ready_order, ctx) =
    helpers.complete_http01_order(ctx, registered_key, domain)

  let #(csr, cert_jwk) = helpers.generate_csr_with_key([domain])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: finalize_order.build(
        ready_order.finalize_url,
        _,
        registered_key,
        csr:,
      ),
      send: helpers.send,
    )

  let assert Ok(_finalized) = finalize_order.response(resp, ready_order.url)

  let #(valid_order, ctx) =
    helpers.poll_order_until_valid(ctx, ready_order, registered_key)

  let assert order.Valid(cert_url) = valid_order.status

  let assert Ok(#(cert_resp, ctx)) =
    acumen.execute(
      ctx,
      build: fetch_certificate.build(cert_url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(pem_chain) = fetch_certificate.response(cert_resp)
  assert string.starts_with(pem_chain, "-----BEGIN CERTIFICATE-----")

  let assert Ok(cert_der) = pem_to_der(cert_resp.body)
  #(cert_der, cert_jwk, registered_key, ctx)
}

fn issue_certificate(
  domain: String,
) -> #(BitArray, acumen.RegisteredKey, acumen.Context) {
  let #(_account, registered_key, ctx) = helpers.setup_registered_account()

  let #(ready_order, ctx) =
    helpers.complete_http01_order(ctx, registered_key, domain)

  let csr = helpers.generate_csr([domain])

  let assert Ok(#(resp, ctx)) =
    acumen.execute(
      ctx,
      build: finalize_order.build(
        ready_order.finalize_url,
        _,
        registered_key,
        csr:,
      ),
      send: helpers.send,
    )

  let assert Ok(_finalized) = finalize_order.response(resp, ready_order.url)

  let #(valid_order, ctx) =
    helpers.poll_order_until_valid(ctx, ready_order, registered_key)

  let assert order.Valid(cert_url) = valid_order.status

  let assert Ok(#(cert_resp, ctx)) =
    acumen.execute(
      ctx,
      build: fetch_certificate.build(cert_url, _, registered_key),
      send: helpers.send,
    )

  let assert Ok(pem_chain) = fetch_certificate.response(cert_resp)
  assert string.starts_with(pem_chain, "-----BEGIN CERTIFICATE-----")

  let assert Ok(cert_der) = pem_to_der(cert_resp.body)
  #(cert_der, registered_key, ctx)
}

fn pem_to_der(pem: String) -> Result(BitArray, Nil) {
  let start_marker = "-----BEGIN CERTIFICATE-----"
  let end_marker = "-----END CERTIFICATE-----"

  use #(_, after_start) <- result.try(string.split_once(pem, start_marker))
  use #(base64_content, _) <- result.try(string.split_once(
    after_start,
    end_marker,
  ))

  let cleaned =
    base64_content
    |> string.replace("\n", "")
    |> string.replace("\r", "")
    |> string.replace(" ", "")

  bit_array.base64_decode(cleaned)
}
