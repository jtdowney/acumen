import acumen
import acumen/challenge.{type Challenge}
import acumen/url.{type Url}
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/string
import gleam/time/timestamp.{type Timestamp}
import gose
import gose/jose/jwk
import kryptos/ec
import kryptos/hash
import qcheck

pub fn decodes_http01_challenge_test() {
  let body =
    json.object([
      #("type", json.string("http-01")),
      #("status", json.string("pending")),
      #("url", json.string("https://example.com/chall/1")),
      #("token", json.string("abc123")),
    ])
    |> json.to_string

  let assert Ok(chall) = json.parse(body, challenge.decoder())

  assert challenge.status(chall) == challenge.Pending
  let assert Ok(token) = challenge.token(chall)
  assert token == "abc123"
  let assert challenge.Http01Challenge(..) = chall
}

pub fn decodes_dns01_challenge_with_timestamp_test() {
  let body =
    json.object([
      #("type", json.string("dns-01")),
      #("status", json.string("valid")),
      #("url", json.string("https://example.com/chall/2")),
      #("token", json.string("xyz789")),
      #("validated", json.string("2024-01-15T10:30:00Z")),
    ])
    |> json.to_string

  let assert Ok(chall) = json.parse(body, challenge.decoder())

  assert challenge.status(chall) == challenge.Valid
  let assert challenge.Dns01Challenge(validated:, ..) = chall
  assert option.is_some(validated)
}

pub fn decodes_unknown_challenge_as_none_test() {
  let body =
    json.object([
      #("type", json.string("unknown-99")),
      #("status", json.string("pending")),
      #("url", json.string("https://example.com/chall/3")),
      #("token", json.string("token123")),
    ])
    |> json.to_string

  let assert Error(_) = json.parse(body, challenge.decoder())
}

pub fn key_authorization_format_property_test() {
  let key = gose.generate_ec(ec.P256)
  let assert Ok(kid) = url.from_string("https://example.com/acct/1")
  let registered = acumen.RegisteredKey(jwk: key, kid: kid)

  use token <- qcheck.given(
    qcheck.non_empty_string_from(qcheck.alphanumeric_ascii_codepoint()),
  )

  let assert Ok(chall_url) = url.from_string("https://example.com/chall/1")
  let http_challenge =
    challenge.Http01Challenge(
      url: chall_url,
      status: challenge.Pending,
      token: token,
      validated: option.None,
      error: option.None,
    )

  let assert Ok(key_auth) =
    challenge.key_authorization(http_challenge, registered)

  assert string.starts_with(key_auth, token <> ".")
  assert !string.contains(key_auth, "=")
  assert string.contains(key_auth, ".")
}

pub fn key_authorization_works_for_dns01_test() {
  let key = gose.generate_ec(ec.P256)
  let assert Ok(kid) = url.from_string("https://example.com/acct/1")
  let registered = acumen.RegisteredKey(jwk: key, kid: kid)
  let dns_challenge = make_challenge(challenge.Dns01Challenge)

  let assert Ok(thumbprint) = jwk.thumbprint(key, hash.Sha256)
  let expected = "token." <> thumbprint

  let assert Ok(key_auth) =
    challenge.key_authorization(dns_challenge, registered)
  assert key_auth == expected
}

pub fn key_authorization_works_for_dns_account01_test() {
  let key = gose.generate_ec(ec.P256)
  let assert Ok(kid) = url.from_string("https://example.com/acct/1")
  let registered = acumen.RegisteredKey(jwk: key, kid: kid)
  let dns_account_challenge = make_challenge(challenge.DnsAccount01Challenge)

  let assert Ok(thumbprint) = jwk.thumbprint(key, hash.Sha256)
  let expected = "token." <> thumbprint

  let assert Ok(key_auth) =
    challenge.key_authorization(dns_account_challenge, registered)
  assert key_auth == expected
}

pub fn key_authorization_works_for_tls_alpn01_test() {
  let key = gose.generate_ec(ec.P256)
  let assert Ok(kid) = url.from_string("https://example.com/acct/1")
  let registered = acumen.RegisteredKey(jwk: key, kid: kid)
  let tls_challenge = make_challenge(challenge.TlsAlpn01Challenge)

  let assert Ok(thumbprint) = jwk.thumbprint(key, hash.Sha256)
  let expected = "token." <> thumbprint

  let assert Ok(key_auth) =
    challenge.key_authorization(tls_challenge, registered)
  assert key_auth == expected
}

pub fn key_authorization_rejects_persist_challenge_test() {
  let key = gose.generate_ec(ec.P256)
  let assert Ok(kid) = url.from_string("https://example.com/acct/1")
  let registered = acumen.RegisteredKey(jwk: key, kid: kid)
  let persist = make_dns_persist01()

  let assert Error(acumen.InvalidChallenge(_)) =
    challenge.key_authorization(persist, registered)
}

pub fn url_returns_url_for_token_challenges_test() {
  let chall = make_challenge(challenge.Http01Challenge)
  let assert Ok(expected) = url.from_string("https://example.com/chall")
  assert challenge.url(chall) == expected
}

pub fn url_returns_url_for_persist_challenge_test() {
  let chall = make_dns_persist01()
  let assert Ok(expected) = url.from_string("https://example.com/chall")
  assert challenge.url(chall) == expected
}

pub fn token_returns_ok_for_token_challenges_test() {
  let chall = make_challenge(challenge.Http01Challenge)
  let assert Ok("token") = challenge.token(chall)
}

pub fn token_returns_error_for_persist_challenge_test() {
  let chall = make_dns_persist01()
  let assert Error(Nil) = challenge.token(chall)
}

pub fn issuer_domain_names_returns_ok_for_persist_test() {
  let chall = make_dns_persist01()
  let assert Ok(["letsencrypt.org"]) = challenge.issuer_domain_names(chall)
}

pub fn issuer_domain_names_returns_error_for_token_challenges_test() {
  let chall = make_challenge(challenge.Http01Challenge)
  let assert Error(Nil) = challenge.issuer_domain_names(chall)
}

fn make_challenge(
  constructor: fn(
    Url,
    challenge.Status,
    String,
    Option(Timestamp),
    Option(acumen.AcmeError),
  ) ->
    Challenge,
) -> Challenge {
  let assert Ok(chall_url) = url.from_string("https://example.com/chall")
  constructor(chall_url, challenge.Pending, "token", option.None, option.None)
}

fn make_dns_persist01() -> Challenge {
  let assert Ok(chall_url) = url.from_string("https://example.com/chall")
  challenge.DnsPersist01Challenge(
    url: chall_url,
    status: challenge.Pending,
    validated: option.None,
    error: option.None,
    issuer_domain_names: ["letsencrypt.org"],
  )
}

pub fn find_by_type_test() {
  let challenges = [
    make_challenge(challenge.Http01Challenge),
    make_challenge(challenge.Dns01Challenge),
    make_challenge(challenge.TlsAlpn01Challenge),
    make_dns_persist01(),
    make_challenge(challenge.DnsAccount01Challenge),
  ]
  [
    challenge.Http01,
    challenge.Dns01,
    challenge.TlsAlpn01,
    challenge.DnsPersist01,
    challenge.DnsAccount01,
  ]
  |> list.each(fn(type_) {
    let assert Ok(found) = challenge.find_by_type(challenges, of: type_)
    assert challenge.challenge_type_of(found) == type_
  })
}

pub fn find_by_type_returns_error_when_not_found_test() {
  let challenges = [
    make_challenge(challenge.Dns01Challenge),
    make_challenge(challenge.TlsAlpn01Challenge),
  ]

  let result = challenge.find_by_type(challenges, of: challenge.Http01)
  assert result == Error(Nil)
}

pub fn decodes_dns_persist01_challenge_test() {
  let body =
    json.object([
      #("type", json.string("dns-persist-01")),
      #("status", json.string("pending")),
      #("url", json.string("https://example.com/chall/4")),
      #(
        "issuer-domain-names",
        json.array(["letsencrypt.org", "r3.letsencrypt.org"], json.string),
      ),
    ])
    |> json.to_string

  let assert Ok(chall) = json.parse(body, challenge.decoder())

  assert challenge.status(chall) == challenge.Pending
  let assert Ok(names) = challenge.issuer_domain_names(chall)
  assert names == ["letsencrypt.org", "r3.letsencrypt.org"]
}

pub fn decodes_dns_persist01_challenge_with_timestamp_test() {
  let body =
    json.object([
      #("type", json.string("dns-persist-01")),
      #("status", json.string("valid")),
      #("url", json.string("https://example.com/chall/5")),
      #("issuer-domain-names", json.array(["letsencrypt.org"], json.string)),
      #("validated", json.string("2024-01-15T10:30:00Z")),
    ])
    |> json.to_string

  let assert Ok(chall) = json.parse(body, challenge.decoder())

  assert challenge.status(chall) == challenge.Valid
  let assert challenge.DnsPersist01Challenge(validated:, ..) = chall
  assert option.is_some(validated)
}

pub fn decodes_invalid_challenge_with_error_test() {
  let body =
    json.object([
      #("type", json.string("http-01")),
      #("status", json.string("invalid")),
      #("url", json.string("https://example.com/chall/1")),
      #("token", json.string("abc123")),
      #(
        "error",
        json.object([
          #("type", json.string("urn:ietf:params:acme:error:connection")),
          #("detail", json.string("Could not connect to example.com")),
        ]),
      ),
    ])
    |> json.to_string

  let assert Ok(chall) = json.parse(body, challenge.decoder())

  assert challenge.status(chall) == challenge.Invalid
  let assert challenge.Http01Challenge(error:, ..) = chall
  let assert option.Some(acumen.ConnectionError(detail)) = error
  assert detail == "Could not connect to example.com"
}

pub fn decodes_challenge_error_with_instance_test() {
  let body =
    json.object([
      #("type", json.string("http-01")),
      #("status", json.string("invalid")),
      #("url", json.string("https://example.com/chall/1")),
      #("token", json.string("abc123")),
      #(
        "error",
        json.object([
          #(
            "type",
            json.string("urn:ietf:params:acme:error:userActionRequired"),
          ),
          #("detail", json.string("Terms of service must be accepted")),
          #("instance", json.string("https://example.com/tos")),
        ]),
      ),
    ])
    |> json.to_string

  let assert Ok(chall) = json.parse(body, challenge.decoder())
  let assert challenge.Http01Challenge(error:, ..) = chall
  let assert option.Some(acumen.UserActionRequired(detail, instance)) = error
  assert detail == "Terms of service must be accepted"
  assert instance == option.Some("https://example.com/tos")
}

pub fn decodes_challenge_error_with_subproblems_test() {
  let body =
    json.object([
      #("type", json.string("http-01")),
      #("status", json.string("invalid")),
      #("url", json.string("https://example.com/chall/1")),
      #("token", json.string("abc123")),
      #(
        "error",
        json.object([
          #("type", json.string("urn:ietf:params:acme:error:compound")),
          #("detail", json.string("Multiple errors")),
          #(
            "subproblems",
            json.preprocessed_array([
              json.object([
                #("type", json.string("urn:ietf:params:acme:error:dns")),
                #("detail", json.string("DNS lookup failed")),
              ]),
            ]),
          ),
        ]),
      ),
    ])
    |> json.to_string

  let assert Ok(chall) = json.parse(body, challenge.decoder())
  let assert challenge.Http01Challenge(error:, ..) = chall
  let assert option.Some(acumen.CompoundError(detail, subproblems)) = error
  assert detail == "Multiple errors"
  let assert [sub] = subproblems
  assert sub.type_ == "urn:ietf:params:acme:error:dns"
  assert sub.detail == "DNS lookup failed"
}

pub fn dns01_txt_record_test() {
  let assert Ok(value) = challenge.dns01_txt_record("token.thumbprint")
  assert value == "61rBZ_4knHblO0MNoxFsXZ_eTFUHum0B6IVRbhvUn5I"
}

pub fn dns_account01_txt_record_test() {
  let assert Ok(account_url) = url.from_string("https://example.com/acct/1")
  let assert Ok(#(name, value)) =
    challenge.dns_account01_txt_record(
      "example.com",
      account_url,
      "token.thumbprint",
    )
  assert name == "_acme-challenge_wbklsihqkqsa22nu.example.com"
  assert value == "61rBZ_4knHblO0MNoxFsXZ_eTFUHum0B6IVRbhvUn5I"
}

pub fn dns_persist01_txt_record_test() {
  let assert Ok(account_url) = url.from_string("https://example.com/acct/1")
  let record =
    challenge.dns_persist01_txt_record("letsencrypt.org", account_url)
  assert record == "letsencrypt.org; accounturi=https://example.com/acct/1"
}

pub fn decodes_tls_alpn01_challenge_test() {
  let body =
    json.object([
      #("type", json.string("tls-alpn-01")),
      #("status", json.string("pending")),
      #("url", json.string("https://example.com/chall/7")),
      #("token", json.string("alpn-token")),
    ])
    |> json.to_string

  let assert Ok(chall) = json.parse(body, challenge.decoder())

  assert challenge.status(chall) == challenge.Pending
  let assert Ok(token) = challenge.token(chall)
  assert token == "alpn-token"
  let assert challenge.TlsAlpn01Challenge(..) = chall
}

pub fn decodes_dns_account01_challenge_test() {
  let body =
    json.object([
      #("type", json.string("dns-account-01")),
      #("status", json.string("pending")),
      #("url", json.string("https://example.com/chall/6")),
      #("token", json.string("acct-token")),
    ])
    |> json.to_string

  let assert Ok(chall) = json.parse(body, challenge.decoder())

  assert challenge.status(chall) == challenge.Pending
  let assert Ok(token) = challenge.token(chall)
  assert token == "acct-token"
  let assert challenge.DnsAccount01Challenge(..) = chall
}

pub fn dns_account_label_test() {
  let assert Ok(label) =
    challenge.dns_account_label("https://example.com/acct/1")
  assert label == "wbklsihqkqsa22nu"
}

pub fn dns_account_label_is_16_lowercase_base32_property_test() {
  use account_url <- qcheck.given(
    qcheck.non_empty_string_from(qcheck.alphanumeric_ascii_codepoint())
    |> qcheck.map(fn(s) { "https://example.com/acct/" <> s }),
  )

  let assert Ok(label) = challenge.dns_account_label(account_url)
  assert string.length(label) == 16
  assert label == string.lowercase(label)
}
