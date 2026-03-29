import acumen
import acumen/url
import gleam/dict
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/list
import gleam/option
import gleam/string
import gleam/time/timestamp
import gleam/uri
import qcheck
import simplifile
import support/fixtures
import unitest

pub fn main() -> Nil {
  unitest.run(
    unitest.Options(..unitest.default_options(), ignored_tags: ["integration"]),
  )
}

pub fn version_matches_gleam_toml_test() {
  let assert Ok(toml) = simplifile.read("gleam.toml")
  let assert Ok(version_line) =
    toml
    |> string.split("\n")
    |> list.find(fn(line) { string.starts_with(string.trim(line), "version") })

  let toml_version =
    version_line
    |> string.replace("version = ", "")
    |> string.replace("\"", "")
    |> string.trim

  assert acumen.version == toml_version
}

pub fn retry_after_extracts_seconds_test() {
  let resp =
    response.new(503)
    |> response.set_header("retry-after", "120")
    |> response.set_body("")

  let assert Ok(acumen.RetryAfterSeconds(seconds)) = acumen.retry_after(resp)
  assert seconds == 120
}

pub fn retry_after_parses_http_date_test() {
  let resp =
    response.new(503)
    |> response.set_header("retry-after", "Sun, 06 Nov 1994 08:49:37 GMT")
    |> response.set_body("")

  let assert Ok(acumen.RetryAfterTimestamp(ts)) = acumen.retry_after(resp)
  assert ts == timestamp.from_unix_seconds(784_111_777)
}

pub fn retry_after_returns_error_for_missing_header_test() {
  let resp =
    response.new(200)
    |> response.set_body("")

  let assert Error(Nil) = acumen.retry_after(resp)
}

pub fn retry_after_returns_error_for_invalid_value_test() {
  let resp =
    response.new(503)
    |> response.set_header("retry-after", "not-a-number")
    |> response.set_body("")

  let assert Error(Nil) = acumen.retry_after(resp)
}

pub fn retry_after_rejects_negative_seconds_test() {
  let resp =
    response.new(503)
    |> response.set_header("retry-after", "-1")
    |> response.set_body("")

  let assert Error(Nil) = acumen.retry_after(resp)
}

pub fn external_account_required_returns_true_when_set_test() {
  let directory =
    fixtures.test_directory_with_meta(
      terms_of_service: option.None,
      external_account_required: True,
    )
  assert acumen.external_account_required(directory) == True
}

pub fn external_account_required_returns_false_when_unset_test() {
  let directory =
    fixtures.test_directory_with_meta(
      terms_of_service: option.None,
      external_account_required: False,
    )
  assert acumen.external_account_required(directory) == False
}

pub fn external_account_required_returns_false_when_no_meta_test() {
  let directory = fixtures.test_directory()
  assert acumen.external_account_required(directory) == False
}

pub fn terms_of_service_returns_ok_when_present_test() {
  let assert Ok(tos_uri) = uri.parse("https://example.com/tos")
  let directory =
    fixtures.test_directory_with_meta(
      terms_of_service: option.Some(tos_uri),
      external_account_required: False,
    )
  let assert Ok(uri) = acumen.terms_of_service(directory)
  assert uri == tos_uri
}

pub fn terms_of_service_returns_error_when_missing_test() {
  let directory =
    fixtures.test_directory_with_meta(
      terms_of_service: option.None,
      external_account_required: False,
    )
  let assert Error(Nil) = acumen.terms_of_service(directory)
}

pub fn terms_of_service_returns_error_when_no_meta_test() {
  let directory = fixtures.test_directory()
  let assert Error(Nil) = acumen.terms_of_service(directory)
}

pub fn profiles_returns_dict_when_present_test() {
  let profiles_dict =
    dict.from_list([
      #("tlsserver", "TLS server certificates"),
      #("codesigning", "Code signing certificates"),
    ])
  let directory = fixtures.test_directory_with_profiles(profiles_dict)
  assert acumen.profiles(directory) == profiles_dict
}

pub fn profiles_returns_empty_dict_when_missing_test() {
  let directory = fixtures.test_directory_with_profiles(dict.new())
  assert dict.is_empty(acumen.profiles(directory))
}

pub fn profiles_returns_empty_dict_when_no_meta_test() {
  let directory = fixtures.test_directory()
  assert dict.is_empty(acumen.profiles(directory))
}

pub fn parses_complete_directory_response_test() {
  let body =
    json.object([
      #("newNonce", json.string("https://example.com/new-nonce")),
      #("newAccount", json.string("https://example.com/new-acct")),
      #("newOrder", json.string("https://example.com/new-order")),
      #("revokeCert", json.string("https://example.com/revoke-cert")),
      #("keyChange", json.string("https://example.com/key-change")),
      #("newAuthz", json.string("https://example.com/new-authz")),
      #(
        "meta",
        json.object([
          #("termsOfService", json.string("https://example.com/tos")),
          #("website", json.string("https://example.com")),
          #("caaIdentities", json.array(["example.com"], json.string)),
          #("externalAccountRequired", json.bool(True)),
        ]),
      ),
    ])
    |> json.to_string

  let resp =
    response.new(200)
    |> response.set_body(body)

  let assert Ok(directory) = acumen.directory(resp)

  assert url.to_uri(directory.new_nonce).path == "/new-nonce"
  assert url.to_uri(directory.new_account).path == "/new-acct"
  assert url.to_uri(directory.new_order).path == "/new-order"
  assert url.to_uri(directory.revoke_cert).path == "/revoke-cert"
  assert url.to_uri(directory.key_change).path == "/key-change"
  let assert option.Some(new_authz) = directory.new_authz
  assert url.to_uri(new_authz).path == "/new-authz"

  let assert option.Some(meta) = directory.meta
  let assert option.Some(tos) = meta.terms_of_service
  assert tos.path == "/tos"
  let assert option.Some(website) = meta.website
  assert website.host == option.Some("example.com")
  assert meta.caa_identities == ["example.com"]
  assert meta.external_account_required
}

pub fn parses_directory_without_meta_test() {
  let body =
    json.object([
      #("newNonce", json.string("https://example.com/new-nonce")),
      #("newAccount", json.string("https://example.com/new-acct")),
      #("newOrder", json.string("https://example.com/new-order")),
      #("revokeCert", json.string("https://example.com/revoke-cert")),
      #("keyChange", json.string("https://example.com/key-change")),
    ])
    |> json.to_string

  let resp =
    response.new(200)
    |> response.set_body(body)

  let assert Ok(directory) = acumen.directory(resp)

  assert directory.meta == option.None
  assert directory.new_authz == option.None
  assert directory.renewal_info == option.None
}

pub fn parses_renewal_info_in_directory_test() {
  let body =
    json.object([
      #("newNonce", json.string("https://example.com/new-nonce")),
      #("newAccount", json.string("https://example.com/new-acct")),
      #("newOrder", json.string("https://example.com/new-order")),
      #("revokeCert", json.string("https://example.com/revoke-cert")),
      #("keyChange", json.string("https://example.com/key-change")),
      #("renewalInfo", json.string("https://example.com/renewal-info")),
    ])
    |> json.to_string

  let resp =
    response.new(200)
    |> response.set_body(body)

  let assert Ok(directory) = acumen.directory(resp)
  let assert option.Some(ri) = directory.renewal_info
  assert ri.path == "/renewal-info"
}

pub fn directory_rejects_non_200_status_code_test() {
  let resp =
    response.new(404)
    |> response.set_body("{}")

  let assert Error(acumen.InvalidResponse(msg)) = acumen.directory(resp)
  assert msg == "expected status 200, got 404"
}

pub fn directory_rejects_malformed_json_test() {
  let resp =
    response.new(200)
    |> response.set_body("not valid json")

  let assert Error(acumen.JsonParseError(_)) = acumen.directory(resp)
}

pub fn parses_profiles_dict_in_meta_test() {
  let body =
    json.object([
      #("newNonce", json.string("https://example.com/new-nonce")),
      #("newAccount", json.string("https://example.com/new-acct")),
      #("newOrder", json.string("https://example.com/new-order")),
      #("revokeCert", json.string("https://example.com/revoke-cert")),
      #("keyChange", json.string("https://example.com/key-change")),
      #(
        "meta",
        json.object([
          #(
            "profiles",
            json.object([
              #("tlsserver", json.string("TLS server certificates")),
              #("codesigning", json.string("Code signing certificates")),
            ]),
          ),
        ]),
      ),
    ])
    |> json.to_string

  let resp =
    response.new(200)
    |> response.set_body(body)

  let assert Ok(directory) = acumen.directory(resp)

  let profiles = acumen.profiles(directory)
  let assert Ok(tlsserver_desc) = dict.get(profiles, "tlsserver")
  assert tlsserver_desc == "TLS server certificates"
  let assert Ok(codesigning_desc) = dict.get(profiles, "codesigning")
  assert codesigning_desc == "Code signing certificates"
}

pub fn identifier_decoder_test() {
  [
    #("dns", "example.com", acumen.DnsIdentifier("example.com")),
    #("ip", "192.0.2.1", acumen.IpIdentifier("192.0.2.1")),
  ]
  |> list.each(fn(case_) {
    let #(type_, value, expected) = case_
    let body =
      json.object([
        #("type", json.string(type_)),
        #("value", json.string(value)),
      ])
      |> json.to_string

    let assert Ok(identifier) = json.parse(body, acumen.identifier_decoder())
    assert identifier == expected
  })
}

pub fn identifier_decoder_dns_roundtrip_property_test() {
  use value <- qcheck.given(
    qcheck.string_from(qcheck.printable_ascii_codepoint()),
  )

  let dns_json =
    json.object([
      #("type", json.string("dns")),
      #("value", json.string(value)),
    ])
    |> json.to_string

  let assert Ok(acumen.DnsIdentifier(decoded_value)) =
    json.parse(dns_json, acumen.identifier_decoder())
  assert decoded_value == value
}

pub fn identifier_decoder_ip_roundtrip_property_test() {
  use value <- qcheck.given(
    qcheck.string_from(qcheck.printable_ascii_codepoint()),
  )

  let ip_json =
    json.object([
      #("type", json.string("ip")),
      #("value", json.string(value)),
    ])
    |> json.to_string

  let assert Ok(acumen.IpIdentifier(decoded_value)) =
    json.parse(ip_json, acumen.identifier_decoder())
  assert decoded_value == value
}

pub fn identifier_decoder_rejects_unknown_type_test() {
  let body =
    json.object([
      #("type", json.string("unknown")),
      #("value", json.string("example.com")),
    ])
    |> json.to_string

  let assert Error(_) = json.parse(body, acumen.identifier_decoder())
}

fn make_error_response(
  type_: String,
  detail: String,
) -> response.Response(String) {
  let body =
    json.object([
      #("type", json.string(type_)),
      #("detail", json.string(detail)),
    ])
    |> json.to_string

  response.new(400)
  |> response.set_header("replay-nonce", "nonce")
  |> response.set_body(body)
}

fn build_and_send(ctx, resp) {
  acumen.execute(ctx, fn(_) { Ok(request.new()) }, fn(_) { Ok(resp) })
}

pub fn maps_short_type_name_to_error_test() {
  let ctx = fixtures.test_context()
  let resp = make_error_response("acme:error:malformed", "Request is malformed")

  let assert Error(acumen.ProtocolError(
    error: acumen.MalformedError(detail),
    context: _,
  )) = build_and_send(ctx, resp)
  assert detail == "Request is malformed"
}

pub fn maps_all_standard_error_types_test() {
  let ctx = fixtures.test_context()

  let test_cases = [
    #("accountDoesNotExist", fn(d) { acumen.AccountDoesNotExist(d) }),
    #("alreadyReplaced", fn(d) { acumen.AlreadyReplaced(d) }),
    #("alreadyRevoked", fn(d) { acumen.AlreadyRevoked(d) }),
    #("badCSR", fn(d) { acumen.BadCsr(d) }),
    #("badPublicKey", fn(d) { acumen.BadPublicKey(d) }),
    #("badRevocationReason", fn(d) { acumen.BadRevocationReason(d) }),
    #("badSignatureAlgorithm", fn(d) { acumen.BadSignatureAlgorithm(d) }),
    #("caa", fn(d) { acumen.CaaError(d) }),
    #("connection", fn(d) { acumen.ConnectionError(d) }),
    #("dns", fn(d) { acumen.DnsError(d) }),
    #("externalAccountRequired", fn(d) { acumen.ExternalAccountRequired(d) }),
    #("incorrectResponse", fn(d) { acumen.IncorrectResponse(d) }),
    #("invalidContact", fn(d) { acumen.InvalidContact(d) }),
    #("malformed", fn(d) { acumen.MalformedError(d) }),
    #("orderNotReady", fn(d) { acumen.OrderNotReady(d) }),
    #("rateLimited", fn(d) { acumen.RateLimited(d) }),
    #("rejectedIdentifier", fn(d) { acumen.RejectedIdentifier(d) }),
    #("serverInternal", fn(d) { acumen.ServerInternalError(d) }),
    #("tls", fn(d) { acumen.TlsError(d) }),
    #("unauthorized", fn(d) { acumen.Unauthorized(d) }),
    #("unsupportedContact", fn(d) { acumen.UnsupportedContact(d) }),
    #("unsupportedIdentifier", fn(d) { acumen.UnsupportedIdentifier(d) }),
  ]

  let detail = "test detail"
  test_cases
  |> list.each(fn(test_case) {
    let #(type_name, expected_fn) = test_case
    let resp =
      make_error_response("urn:ietf:params:acme:error:" <> type_name, detail)

    let assert Error(acumen.ProtocolError(error: err, context: _)) =
      build_and_send(ctx, resp)
    assert err == expected_fn(detail)
  })
}

pub fn unknown_type_returns_unknown_error_test() {
  let ctx = fixtures.test_context()
  let resp =
    make_error_response(
      "urn:ietf:params:acme:error:newFutureError",
      "Some new error",
    )

  let assert Error(acumen.ProtocolError(
    error: acumen.UnknownError(type_, detail, status),
    context: _,
  )) = build_and_send(ctx, resp)
  assert type_ == "urn:ietf:params:acme:error:newFutureError"
  assert detail == "Some new error"
  assert status == option.Some(400)
}

pub fn compound_error_includes_subproblems_test() {
  let ctx = fixtures.test_context()

  let body =
    json.object([
      #("type", json.string("urn:ietf:params:acme:error:compound")),
      #("detail", json.string("Multiple errors occurred")),
      #(
        "subproblems",
        json.preprocessed_array([
          json.object([
            #("type", json.string("urn:ietf:params:acme:error:dns")),
            #("detail", json.string("DNS lookup failed")),
            #(
              "identifier",
              json.object([
                #("type", json.string("dns")),
                #("value", json.string("example.com")),
              ]),
            ),
          ]),
          json.object([
            #("type", json.string("urn:ietf:params:acme:error:caa")),
            #("detail", json.string("CAA record forbids")),
          ]),
        ]),
      ),
    ])
    |> json.to_string

  let resp =
    response.new(400)
    |> response.set_header("replay-nonce", "nonce")
    |> response.set_body(body)

  let assert Error(acumen.ProtocolError(
    error: acumen.CompoundError(detail, subproblems),
    context: _,
  )) = build_and_send(ctx, resp)

  assert detail == "Multiple errors occurred"
  assert list.length(subproblems) == 2

  let assert [first, second] = subproblems

  assert first.type_ == "urn:ietf:params:acme:error:dns"
  assert first.detail == "DNS lookup failed"
  assert first.identifier == option.Some(acumen.DnsIdentifier("example.com"))

  assert second.type_ == "urn:ietf:params:acme:error:caa"
  assert second.detail == "CAA record forbids"
  assert second.identifier == option.None
}

pub fn compound_error_with_empty_subproblems_test() {
  let ctx = fixtures.test_context()

  let body =
    json.object([
      #("type", json.string("urn:ietf:params:acme:error:compound")),
      #("detail", json.string("Multiple errors occurred")),
      #("subproblems", json.preprocessed_array([])),
    ])
    |> json.to_string

  let resp =
    response.new(400)
    |> response.set_header("replay-nonce", "nonce")
    |> response.set_body(body)

  let assert Error(acumen.ProtocolError(
    error: acumen.CompoundError(detail, subproblems),
    context: _,
  )) = build_and_send(ctx, resp)

  assert detail == "Multiple errors occurred"
  assert subproblems == []
}

pub fn user_action_required_without_instance_test() {
  let ctx = fixtures.test_context()

  let body =
    json.object([
      #("type", json.string("urn:ietf:params:acme:error:userActionRequired")),
      #("detail", json.string("Please verify your account")),
    ])
    |> json.to_string

  let resp =
    response.new(400)
    |> response.set_header("replay-nonce", "nonce")
    |> response.set_body(body)

  let assert Error(acumen.ProtocolError(
    error: acumen.UserActionRequired(detail, instance),
    context: _,
  )) = build_and_send(ctx, resp)

  assert detail == "Please verify your account"
  assert instance == option.None
}

pub fn user_action_required_includes_instance_test() {
  let ctx = fixtures.test_context()

  let body =
    json.object([
      #("type", json.string("urn:ietf:params:acme:error:userActionRequired")),
      #("detail", json.string("Please verify your account")),
      #("instance", json.string("https://example.com/verify")),
    ])
    |> json.to_string

  let resp =
    response.new(400)
    |> response.set_header("replay-nonce", "nonce")
    |> response.set_body(body)

  let assert Error(acumen.ProtocolError(
    error: acumen.UserActionRequired(detail, instance),
    context: _,
  )) = build_and_send(ctx, resp)

  assert detail == "Please verify your account"
  assert instance == option.Some("https://example.com/verify")
}

pub fn invalid_json_returns_json_parse_error_test() {
  let ctx = fixtures.test_context()

  let resp =
    response.new(400)
    |> response.set_header("replay-nonce", "nonce")
    |> response.set_body("not valid json")

  let assert Error(acumen.ProtocolError(
    error: acumen.JsonParseError(msg),
    context: _,
  )) = build_and_send(ctx, resp)
  assert msg == "failed to parse error response: unexpected byte: 0x6F"
}

pub fn unknown_error_type_property_test() {
  use random_suffix <- qcheck.given(
    qcheck.string_from(qcheck.alphanumeric_ascii_codepoint()),
  )

  let random_type = "futureError_" <> random_suffix
  let ctx = fixtures.test_context()
  let resp =
    make_error_response("urn:ietf:params:acme:error:" <> random_type, "detail")

  let assert Error(acumen.ProtocolError(
    error: acumen.UnknownError(_, _, _),
    context: _,
  )) = build_and_send(ctx, resp)
  Nil
}

pub type TransportFailure {
  NetworkError
}

fn success_response(nonce: String) -> response.Response(String) {
  response.new(200)
  |> response.set_header("replay-nonce", nonce)
  |> response.set_body("{}")
}

fn bad_nonce_response(nonce: String) -> response.Response(String) {
  let body =
    json.object([
      #("type", json.string("urn:ietf:params:acme:error:badNonce")),
      #("detail", json.string("bad nonce")),
    ])
    |> json.to_string

  response.new(400)
  |> response.set_header("replay-nonce", nonce)
  |> response.set_body(body)
}

fn rate_limit_response() -> response.Response(String) {
  let body =
    json.object([
      #("type", json.string("urn:ietf:params:acme:error:rateLimited")),
      #("detail", json.string("too many requests")),
    ])
    |> json.to_string

  response.new(429)
  |> response.set_header("replay-nonce", "new-nonce")
  |> response.set_body(body)
}

fn server_error_response() -> response.Response(String) {
  let body =
    json.object([
      #("type", json.string("urn:ietf:params:acme:error:serverInternal")),
      #("detail", json.string("internal error")),
    ])
    |> json.to_string

  response.new(500)
  |> response.set_header("replay-nonce", "new-nonce")
  |> response.set_body(body)
}

fn simple_build(
  _ctx: acumen.Context,
) -> Result(request.Request(String), acumen.AcmeError) {
  let assert Ok(req) = request.to("https://example.com/test")
  Ok(req)
}

pub fn execute_success_returns_response_and_updated_context_test() {
  let ctx = fixtures.test_context()

  let send = fn(_req) -> Result(response.Response(String), TransportFailure) {
    Ok(success_response("fresh-nonce"))
  }

  let assert Ok(#(resp, new_ctx)) =
    acumen.execute(ctx, build: simple_build, send: send)
  assert resp.status == 200
  assert new_ctx.nonce == "fresh-nonce"
}

pub fn execute_bad_nonce_triggers_retry_test() {
  let ctx = fixtures.test_context()

  let build_request = fn(build_ctx: acumen.Context) -> Result(
    request.Request(String),
    acumen.AcmeError,
  ) {
    let assert Ok(req) = request.to("https://example.com/test")
    Ok(request.set_header(req, "x-test-nonce", build_ctx.nonce))
  }

  let send = fn(req: request.Request(String)) -> Result(
    response.Response(String),
    TransportFailure,
  ) {
    case request.get_header(req, "x-test-nonce") {
      Ok("test-nonce") -> Ok(bad_nonce_response("nonce-2"))
      Ok("nonce-2") -> Ok(bad_nonce_response("nonce-3"))
      _ -> Ok(success_response("final-nonce"))
    }
  }

  let assert Ok(#(resp, new_ctx)) =
    acumen.execute(ctx, build: build_request, send: send)
  assert resp.status == 200
  assert new_ctx.nonce == "final-nonce"
}

pub fn execute_bad_nonce_retry_uses_new_nonce_test() {
  let ctx = fixtures.test_context()

  let build_request = fn(build_ctx: acumen.Context) -> Result(
    request.Request(String),
    acumen.AcmeError,
  ) {
    let assert Ok(req) = request.to("https://example.com/test")
    Ok(request.set_header(req, "x-test-nonce", build_ctx.nonce))
  }

  let send = fn(req: request.Request(String)) -> Result(
    response.Response(String),
    TransportFailure,
  ) {
    case request.get_header(req, "x-test-nonce") {
      Ok("test-nonce") -> Ok(bad_nonce_response("retry-nonce"))
      Ok("retry-nonce") -> Ok(success_response("final-nonce"))
      _ -> panic as "unexpected nonce in request"
    }
  }

  let assert Ok(#(_, new_ctx)) =
    acumen.execute(ctx, build: build_request, send: send)
  assert new_ctx.nonce == "final-nonce"
}

pub fn execute_bad_nonce_exhaustion_returns_error_test() {
  let ctx = fixtures.test_context()

  let send = fn(_req) -> Result(response.Response(String), TransportFailure) {
    Ok(bad_nonce_response("new-nonce"))
  }

  let assert Error(acumen.NonceRetryExhausted) =
    acumen.execute(ctx, build: simple_build, send: send)
}

pub fn execute_rate_limit_returns_protocol_error_test() {
  let ctx = fixtures.test_context()

  let send = fn(_req) -> Result(response.Response(String), TransportFailure) {
    Ok(rate_limit_response())
  }

  let assert Error(acumen.ProtocolError(
    error: acumen.RateLimited(detail),
    context: error_ctx,
  )) = acumen.execute(ctx, build: simple_build, send: send)
  assert detail == "too many requests"
  assert error_ctx.nonce == "new-nonce"
}

pub fn execute_transport_error_returns_transport_error_test() {
  let ctx = fixtures.test_context()

  let send = fn(_req) -> Result(response.Response(String), TransportFailure) {
    Error(NetworkError)
  }

  let assert Error(acumen.TransportError(NetworkError)) =
    acumen.execute(ctx, build: simple_build, send: send)
}

pub fn execute_protocol_error_returns_protocol_error_test() {
  let ctx = fixtures.test_context()

  let send = fn(_req) -> Result(response.Response(String), TransportFailure) {
    Ok(server_error_response())
  }

  let assert Error(acumen.ProtocolError(
    error: acumen.ServerInternalError(detail),
    context: error_ctx,
  )) = acumen.execute(ctx, build: simple_build, send: send)
  assert detail == "internal error"
  assert error_ctx.nonce == "new-nonce"
}

pub fn execute_build_request_error_returns_protocol_error_test() {
  let ctx = fixtures.test_context()

  let build_request = fn(_ctx: acumen.Context) -> Result(
    request.Request(String),
    acumen.AcmeError,
  ) {
    Error(acumen.BadNonce("simulated build error"))
  }

  let send = fn(_req) -> Result(response.Response(String), TransportFailure) {
    panic as "send should not be called"
  }

  let assert Error(acumen.ProtocolError(
    error: acumen.BadNonce("simulated build error"),
    context: error_ctx,
  )) = acumen.execute(ctx, build: build_request, send: send)
  assert error_ctx.nonce == "test-nonce"
}
