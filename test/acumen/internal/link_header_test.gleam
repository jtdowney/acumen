import acumen/internal/link_header
import acumen/url

pub fn finds_single_link_by_rel_test() {
  let input = "<https://example.com/page2>; rel=\"next\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com/page2")
  assert url == expected
}

pub fn returns_error_when_rel_not_found_test() {
  let input = "<https://example.com/page2>; rel=\"prev\""

  assert link_header.find_by_rel(input, rel: "next") == Error(Nil)
}

pub fn finds_link_among_multiple_comma_separated_test() {
  let input =
    "<https://example.com/page1>; rel=\"prev\", <https://example.com/page3>; rel=\"next\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com/page3")
  assert url == expected
}

pub fn finds_first_link_among_multiple_test() {
  let input =
    "<https://example.com/page3>; rel=\"next\", <https://example.com/page1>; rel=\"prev\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com/page3")
  assert url == expected
}

pub fn handles_extra_params_test() {
  let input =
    "<https://example.com/page2>; rel=\"next\"; title=\"next chapter\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com/page2")
  assert url == expected
}

pub fn returns_error_for_empty_string_test() {
  assert link_header.find_by_rel("", rel: "next") == Error(Nil)
}

pub fn returns_error_for_missing_angle_brackets_test() {
  let input = "https://example.com/page2; rel=\"next\""

  assert link_header.find_by_rel(input, rel: "next") == Error(Nil)
}

pub fn handles_url_with_query_params_test() {
  let input = "<https://example.com/orders?cursor=abc123>; rel=\"next\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) =
    url.from_string("https://example.com/orders?cursor=abc123")
  assert url == expected
}

pub fn matches_different_rel_types_test() {
  let input =
    "<https://example.com/>; rel=\"index\", <https://example.com/page2>; rel=\"next\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "index")
  let assert Ok(expected) = url.from_string("https://example.com/")
  assert url == expected
}

pub fn does_not_match_rel_as_substring_test() {
  let input = "<https://example.com/page2>; rel=\"nextthing\""

  assert link_header.find_by_rel(input, rel: "next") == Error(Nil)
}

pub fn handles_multiple_rels_in_quoted_string_test() {
  let input = "<https://example.com/>; rel=\"start next\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com/")
  assert url == expected
}

pub fn handles_multiple_rels_finds_first_match_test() {
  let input = "<https://example.com/>; rel=\"start next\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "start")
  let assert Ok(expected) = url.from_string("https://example.com/")
  assert url == expected
}

pub fn handles_repeated_rel_params_test() {
  let input = "<https://example.com/>; rel=\"prev\"; rel=\"next\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com/")
  assert url == expected
}

pub fn returns_error_for_invalid_uri_test() {
  let input = "<:not-a-valid-uri>; rel=\"next\""

  assert link_header.find_by_rel(input, rel: "next") == Error(Nil)
}

pub fn handles_comma_inside_quoted_param_test() {
  let input =
    "<https://example.com/page2>; rel=\"next\"; title=\"page, two\", <https://example.com/page1>; rel=\"prev\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com/page2")
  assert url == expected

  let assert Ok(url2) = link_header.find_by_rel(input, rel: "prev")
  let assert Ok(expected2) = url.from_string("https://example.com/page1")
  assert url2 == expected2
}

pub fn handles_escaped_quote_in_param_test() {
  let input =
    "<https://example.com/page2>; rel=\"next\"; title=\"say \\\"hello\\\"\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com/page2")
  assert url == expected
}

pub fn handles_case_insensitive_rel_key_test() {
  let input = "<https://example.com>; REL=\"next\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com")
  assert url == expected
}

pub fn handles_unquoted_rel_value_test() {
  let input = "<https://example.com>; rel=next"

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com")
  assert url == expected
}

pub fn returns_error_for_text_before_angle_bracket_test() {
  let input = "garbage<https://example.com>; rel=\"next\""

  assert link_header.find_by_rel(input, rel: "next") == Error(Nil)
}

pub fn returns_error_for_empty_value_after_equals_test() {
  let input = "<https://example.com>; rel="

  assert link_header.find_by_rel(input, rel: "next") == Error(Nil)
}

pub fn returns_error_for_missing_semicolon_before_param_test() {
  let input = "<https://example.com> rel=\"next\""

  assert link_header.find_by_rel(input, rel: "next") == Error(Nil)
}

pub fn returns_error_for_missing_semicolon_between_params_test() {
  let input = "<https://example.com>; rel=\"next\" title=\"foo\""

  assert link_header.find_by_rel(input, rel: "next") == Error(Nil)
}

pub fn returns_error_for_trailing_semicolon_test() {
  let input = "<https://example.com>;"

  assert link_header.find_by_rel(input, rel: "next") == Error(Nil)
}

pub fn returns_error_for_trailing_semicolon_with_spaces_test() {
  let input = "<https://example.com>;  "

  assert link_header.find_by_rel(input, rel: "next") == Error(Nil)
}

pub fn finds_link_with_unquoted_param_before_rel_test() {
  let input = "<https://example.com>; title=foo; rel=\"next\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com")
  assert url == expected
}

pub fn finds_link_with_multiple_unquoted_params_test() {
  let input = "<https://example.com>; type=text; title=foo; rel=\"next\""

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com")
  assert url == expected
}

pub fn finds_link_with_unquoted_rel_after_unquoted_param_test() {
  let input = "<https://example.com>; title=foo; rel=next"

  let assert Ok(url) = link_header.find_by_rel(input, rel: "next")
  let assert Ok(expected) = url.from_string("https://example.com")
  assert url == expected
}
