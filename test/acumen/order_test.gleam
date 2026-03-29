import acumen
import acumen/order
import acumen/url
import gleam/bit_array
import gleam/json
import gleam/option
import kryptos/ec
import support/fixtures

pub fn to_ec_csr_generates_valid_der_for_single_domain_test() {
  let ord = fixtures.test_order([acumen.DnsIdentifier("example.com")])
  let #(private_key, _) = ec.generate_key_pair(ec.P256)

  let assert Ok(csr_der) = order.to_ec_csr(ord, private_key)

  assert_valid_der_sequence(csr_der)
  assert bit_array.byte_size(csr_der) > 200
}

pub fn to_ec_csr_handles_ip_identifier_test() {
  let ord = fixtures.test_order([acumen.IpIdentifier("192.0.2.1")])
  let #(private_key, _) = ec.generate_key_pair(ec.P256)

  let assert Ok(csr_der) = order.to_ec_csr(ord, private_key)

  assert_valid_der_sequence(csr_der)
}

pub fn to_ec_csr_handles_mixed_identifiers_test() {
  let ord =
    fixtures.test_order([
      acumen.DnsIdentifier("example.com"),
      acumen.IpIdentifier("192.0.2.1"),
      acumen.DnsIdentifier("www.example.com"),
    ])
  let #(private_key, _) = ec.generate_key_pair(ec.P256)

  let assert Ok(csr_der) = order.to_ec_csr(ord, private_key)

  assert_valid_der_sequence(csr_der)
}

pub fn to_rsa_csr_generates_valid_der_test() {
  let ord = fixtures.test_order([acumen.DnsIdentifier("example.com")])
  let #(private_key, _) = fixtures.test_rsa_key_pair()

  let assert Ok(csr_der) = order.to_rsa_csr(ord, private_key)

  assert_valid_der_sequence(csr_der)
  assert bit_array.byte_size(csr_der) > 400
}

pub fn to_rsa_csr_handles_mixed_identifiers_test() {
  let ord =
    fixtures.test_order([
      acumen.DnsIdentifier("example.com"),
      acumen.IpIdentifier("192.0.2.1"),
    ])
  let #(private_key, _) = fixtures.test_rsa_key_pair()

  let assert Ok(csr_der) = order.to_rsa_csr(ord, private_key)

  assert_valid_der_sequence(csr_der)
}

pub fn to_ec_csr_generates_valid_der_for_p384_test() {
  let ord = fixtures.test_order([acumen.DnsIdentifier("example.com")])
  let #(private_key, _) = ec.generate_key_pair(ec.P384)

  let assert Ok(csr_der) = order.to_ec_csr(ord, private_key)

  assert_valid_der_sequence(csr_der)
}

pub fn to_ec_csr_generates_valid_der_for_p521_test() {
  let ord = fixtures.test_order([acumen.DnsIdentifier("example.com")])
  let #(private_key, _) = ec.generate_key_pair(ec.P521)

  let assert Ok(csr_der) = order.to_ec_csr(ord, private_key)

  assert_valid_der_sequence(csr_der)
}

pub fn to_ec_csr_rejects_empty_identifiers_test() {
  let ord = fixtures.test_order([])
  let #(private_key, _) = ec.generate_key_pair(ec.P256)

  let assert Error(order.NoIdentifiers) = order.to_ec_csr(ord, private_key)
}

pub fn to_ec_csr_rejects_invalid_ip_identifier_test() {
  let ord = fixtures.test_order([acumen.IpIdentifier("not-an-ip")])
  let #(private_key, _) = ec.generate_key_pair(ec.P256)

  let assert Error(order.InvalidIdentifier) = order.to_ec_csr(ord, private_key)
}

pub fn to_rsa_csr_rejects_invalid_ip_identifier_test() {
  let ord = fixtures.test_order([acumen.IpIdentifier("not-an-ip")])
  let #(private_key, _) = fixtures.test_rsa_key_pair()

  let assert Error(order.InvalidIdentifier) = order.to_rsa_csr(ord, private_key)
}

pub fn to_rsa_csr_rejects_empty_identifiers_test() {
  let ord = fixtures.test_order([])
  let #(private_key, _) = fixtures.test_rsa_key_pair()

  let assert Error(order.NoIdentifiers) = order.to_rsa_csr(ord, private_key)
}

fn assert_valid_der_sequence(der: BitArray) -> Nil {
  let assert <<0x30, _:bits>> = der
  Nil
}

pub fn decodes_invalid_order_with_error_test() {
  let assert Ok(order_url) = url.from_string("https://example.com/order/1")
  let body =
    json.object([
      #("status", json.string("invalid")),
      #(
        "identifiers",
        json.array(
          [acumen.DnsIdentifier("example.com")],
          fixtures.identifier_json,
        ),
      ),
      #(
        "authorizations",
        json.array(["https://example.com/authz/1"], json.string),
      ),
      #("finalize", json.string("https://example.com/finalize/1")),
      #(
        "error",
        json.object([
          #("type", json.string("urn:ietf:params:acme:error:caa")),
          #("detail", json.string("CAA record forbids issuance")),
        ]),
      ),
    ])
    |> json.to_string

  let assert Ok(ord) = json.parse(body, order.decoder(order_url))

  assert ord.status == order.Invalid
  let assert option.Some(acumen.CaaError(detail)) = ord.error
  assert detail == "CAA record forbids issuance"
}

pub fn decodes_pending_order_test() {
  let assert Ok(order_url) = url.from_string("https://example.com/order/1")
  let body =
    json.object(fixtures.minimal_order_fields_with_status(
      ["example.com"],
      "pending",
    ))
    |> json.to_string

  let assert Ok(ord) = json.parse(body, order.decoder(order_url))

  assert ord.status == order.Pending
}

pub fn decodes_ready_order_test() {
  let assert Ok(order_url) = url.from_string("https://example.com/order/1")
  let body =
    json.object(fixtures.minimal_order_fields_with_status(
      ["example.com"],
      "ready",
    ))
    |> json.to_string

  let assert Ok(ord) = json.parse(body, order.decoder(order_url))

  assert ord.status == order.Ready
}

pub fn decodes_processing_order_test() {
  let assert Ok(order_url) = url.from_string("https://example.com/order/1")
  let body =
    json.object(fixtures.minimal_order_fields_with_status(
      ["example.com"],
      "processing",
    ))
    |> json.to_string

  let assert Ok(ord) = json.parse(body, order.decoder(order_url))

  assert ord.status == order.Processing
}

pub fn decodes_valid_order_with_certificate_test() {
  let assert Ok(order_url) = url.from_string("https://example.com/order/1")
  let body =
    json.object([
      #("status", json.string("valid")),
      #(
        "identifiers",
        json.array(
          [acumen.DnsIdentifier("example.com")],
          fixtures.identifier_json,
        ),
      ),
      #(
        "authorizations",
        json.array(["https://example.com/authz/1"], json.string),
      ),
      #("finalize", json.string("https://example.com/finalize/1")),
      #("certificate", json.string("https://example.com/cert/1")),
    ])
    |> json.to_string

  let assert Ok(ord) = json.parse(body, order.decoder(order_url))

  let assert Ok(expected_cert) = url.from_string("https://example.com/cert/1")
  assert ord.status == order.Valid(expected_cert)
}

pub fn decodes_valid_order_without_certificate_fails_test() {
  let assert Ok(order_url) = url.from_string("https://example.com/order/1")
  let body =
    json.object([
      #("status", json.string("valid")),
      #(
        "identifiers",
        json.array(
          [acumen.DnsIdentifier("example.com")],
          fixtures.identifier_json,
        ),
      ),
      #(
        "authorizations",
        json.array(["https://example.com/authz/1"], json.string),
      ),
      #("finalize", json.string("https://example.com/finalize/1")),
    ])
    |> json.to_string

  let assert Error(_) = json.parse(body, order.decoder(order_url))
}

pub fn decodes_order_unknown_status_fails_test() {
  let assert Ok(order_url) = url.from_string("https://example.com/order/1")
  let body =
    json.object(fixtures.minimal_order_fields_with_status(
      ["example.com"],
      "unknown",
    ))
    |> json.to_string

  let assert Error(_) = json.parse(body, order.decoder(order_url))
}
