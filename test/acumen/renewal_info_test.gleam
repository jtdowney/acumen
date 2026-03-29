import acumen
import acumen/renewal_info
import gleam/json
import gleam/list
import gleam/option
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import kryptos/ec
import kryptos/hash
import kryptos/x509
import kryptos/x509/certificate
import qcheck

pub fn cert_id_encodes_aki_and_serial_test() {
  let aki = <<1, 2, 3, 4>>
  let serial = <<5, 6, 7, 8>>
  let id = renewal_info.cert_id(aki, serial)
  assert id == "AQIDBA.BQYHCA"
}

pub fn cert_id_from_certificate_extracts_id_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let now = timestamp.system_time()
  let later = timestamp.add(now, duration.seconds(86_400))
  let validity = x509.Validity(not_before: now, not_after: later)

  let assert Ok(built_cert) =
    certificate.new()
    |> certificate.with_subject(x509.name([x509.cn("test.example.com")]))
    |> certificate.with_validity(validity)
    |> certificate.self_signed_with_ecdsa(private_key, hash.Sha256)

  let assert Ok(parsed_cert) =
    certificate.to_der(built_cert)
    |> certificate.from_der

  let assert Ok(id) = renewal_info.cert_id_from_certificate(parsed_cert)

  let assert Ok(aki) = certificate.authority_key_identifier(parsed_cert)
  let assert option.Some(key_id) = aki.key_identifier
  let serial = certificate.serial_number(parsed_cert)

  let expected_id = renewal_info.cert_id(key_id, serial)
  assert id == expected_id
}

pub fn cert_id_from_certificate_rejects_missing_aki_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let now = timestamp.system_time()
  let later = timestamp.add(now, duration.seconds(86_400))
  let validity = x509.Validity(not_before: now, not_after: later)

  let assert Ok(built_cert) =
    certificate.new()
    |> certificate.with_subject(x509.name([x509.cn("test.example.com")]))
    |> certificate.with_validity(validity)
    |> certificate.with_authority_key_identifier(certificate.AkiExclude)
    |> certificate.self_signed_with_ecdsa(private_key, hash.Sha256)

  let assert Ok(parsed_cert) =
    certificate.to_der(built_cert)
    |> certificate.from_der

  let assert Error(acumen.InvalidRequest(msg)) =
    renewal_info.cert_id_from_certificate(parsed_cert)
  assert msg == "certificate missing Authority Key Identifier extension"
}

pub fn decoder_parses_renewal_info_test() {
  let body =
    json.object([
      #(
        "suggestedWindow",
        json.object([
          #("start", json.string("2026-01-01T00:00:00Z")),
          #("end", json.string("2026-01-08T00:00:00Z")),
        ]),
      ),
      #("explanationURL", json.string("https://example.com/explain")),
    ])
    |> json.to_string

  let assert Ok(info) = json.parse(body, renewal_info.decoder())
  let assert Ok(expected_start) =
    timestamp.parse_rfc3339("2026-01-01T00:00:00Z")
  let assert Ok(expected_end) = timestamp.parse_rfc3339("2026-01-08T00:00:00Z")
  assert info.suggested_window.start == expected_start
  assert info.suggested_window.end == expected_end
  let assert option.Some(url) = info.explanation_url
  assert url.path == "/explain"
}

pub fn decoder_parses_without_explanation_url_test() {
  let body =
    json.object([
      #(
        "suggestedWindow",
        json.object([
          #("start", json.string("2026-01-01T00:00:00Z")),
          #("end", json.string("2026-01-08T00:00:00Z")),
        ]),
      ),
    ])
    |> json.to_string

  let assert Ok(info) = json.parse(body, renewal_info.decoder())
  assert info.explanation_url == option.None
}

pub fn cert_id_has_single_dot_separator_property_test() {
  use #(aki, serial) <- qcheck.given(qcheck.tuple2(
    qcheck.bit_array(),
    qcheck.bit_array(),
  ))

  let id = renewal_info.cert_id(aki, serial)
  let parts = string.split(id, ".")
  assert list.length(parts) == 2
}
