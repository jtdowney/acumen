import acumen
import acumen/url
import gleam/dict
import gleam/string
import integration/helpers
import unitest

pub fn directory_parses_pebble_response_test() {
  use <- unitest.tag("integration")

  let directory = helpers.fetch_directory()

  assert url.to_string(directory.new_nonce)
    == helpers.pebble_url <> "/nonce-plz"
}

pub fn profiles_returns_pebble_profiles_test() {
  use <- unitest.tag("integration")

  let directory = helpers.fetch_directory()
  let profiles = acumen.profiles(directory)
  let assert Ok(_description) = dict.get(profiles, "default")
}

pub fn nonce_fetches_from_server_test() {
  use <- unitest.tag("integration")

  let directory = helpers.fetch_directory()
  let result = helpers.fetch_nonce(directory)

  assert !string.is_empty(result)
}
