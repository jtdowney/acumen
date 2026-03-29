import acumen
import acumen/url
import filepath
import gleam/bool
import gleam/dynamic/decode
import gleam/json
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import gose/jwk
import kryptos/ec
import simplifile

pub type StorageError {
  FileError(simplifile.FileError)
  PemConversionError
  KeyNotFound
  KeyCorrupted(String)
}

pub fn ensure_directory(path: String) -> Result(Nil, StorageError) {
  simplifile.create_directory_all(path)
  |> result.map_error(FileError)
}

pub fn write_certificate(path: String, pem: String) -> Result(Nil, StorageError) {
  simplifile.write(path, pem)
  |> result.map_error(FileError)
}

pub fn write_private_key(
  path: String,
  key: ec.PrivateKey,
) -> Result(Nil, StorageError) {
  use pem <- result.try(
    ec.to_pem(key)
    |> result.replace_error(PemConversionError),
  )
  use _ <- result.try(
    simplifile.write(path, pem)
    |> result.map_error(FileError),
  )
  simplifile.set_permissions_octal(path, 0o600)
  |> result.map_error(FileError)
}

pub fn write_certificate_files(
  cert_path: String,
  key_path: String,
  certificate_pem: String,
  cert_key: ec.PrivateKey,
) -> Result(Nil, StorageError) {
  let cert_dir = filepath.directory_name(cert_path)
  use _ <- result.try(ensure_directory(cert_dir))

  let key_dir = filepath.directory_name(key_path)
  use _ <- result.try(ensure_directory(key_dir))

  use _ <- result.try(write_certificate(cert_path, certificate_pem))
  write_private_key(key_path, cert_key)
}

pub fn generate_account_key() -> acumen.UnregisteredKey {
  jwk.generate_ec(ec.P256)
  |> acumen.UnregisteredKey
}

pub fn generate_certificate_key() -> ec.PrivateKey {
  let #(private, _public) = ec.generate_key_pair(ec.P256)
  private
}

fn account_key_path(storage_path: String) -> String {
  filepath.join(storage_path, "account_key.json")
}

pub fn load_account_key(
  storage_path: String,
) -> Result(acumen.RegisteredKey, StorageError) {
  let path = account_key_path(storage_path)
  use contents <- result.try(
    simplifile.read(path)
    |> result.map_error(fn(err) {
      case err {
        simplifile.Enoent -> KeyNotFound
        other -> FileError(other)
      }
    }),
  )
  use jwk_key <- result.try(
    json.parse(contents, jwk.decoder())
    |> result.replace_error(KeyCorrupted("invalid JSON or JWK format")),
  )
  use kid_string <- result.try(
    jwk.kid(jwk_key)
    |> result.replace_error(KeyCorrupted("missing kid in stored JWK")),
  )
  use kid <- result.try(
    url.from_string(kid_string)
    |> result.replace_error(KeyCorrupted("invalid kid URL")),
  )
  Ok(acumen.RegisteredKey(jwk_key, kid))
}

pub fn save_account_key(
  storage_path: String,
  registered_key: acumen.RegisteredKey,
) -> Result(Nil, StorageError) {
  let path = account_key_path(storage_path)
  let jwk_with_kid =
    jwk.with_kid(registered_key.jwk, url.to_string(registered_key.kid))
  let json_string = json.to_string(jwk.to_json(jwk_with_kid))
  use _ <- result.try(ensure_directory(storage_path))
  use _ <- result.try(
    simplifile.write(path, json_string)
    |> result.map_error(FileError),
  )
  simplifile.set_permissions_octal(path, 0o600)
  |> result.map_error(FileError)
}

pub type AriCache {
  AriCache(
    next_check: Timestamp,
    window_start: Timestamp,
    window_end: Timestamp,
    renewal_at: Timestamp,
  )
}

fn ari_cache_path(storage_path: String) -> String {
  filepath.join(storage_path, "ari_cache.json")
}

fn unix_timestamp_decoder() -> decode.Decoder(Timestamp) {
  decode.int |> decode.map(timestamp.from_unix_seconds)
}

fn ari_cache_decoder() -> decode.Decoder(#(String, AriCache)) {
  use saved_cert_id <- decode.field("cert_id", decode.string)
  use next_check <- decode.field("next_check", unix_timestamp_decoder())
  use window_start <- decode.field("window_start", unix_timestamp_decoder())
  use window_end <- decode.field("window_end", unix_timestamp_decoder())
  use renewal_at <- decode.field("renewal_at", unix_timestamp_decoder())
  decode.success(#(
    saved_cert_id,
    AriCache(next_check:, window_start:, window_end:, renewal_at:),
  ))
}

pub fn load_ari_cache(
  storage_path: String,
  cert_id: String,
) -> Result(AriCache, Nil) {
  let path = ari_cache_path(storage_path)
  use contents <- result.try(
    simplifile.read(path)
    |> result.replace_error(Nil),
  )
  use #(saved_cert_id, cache) <- result.try(
    json.parse(contents, ari_cache_decoder())
    |> result.replace_error(Nil),
  )
  use <- bool.guard(when: saved_cert_id != cert_id, return: Error(Nil))
  Ok(cache)
}

fn timestamp_to_unix(ts: Timestamp) -> Int {
  let #(seconds, _nanoseconds) = timestamp.to_unix_seconds_and_nanoseconds(ts)
  seconds
}

pub fn save_ari_cache(
  storage_path: String,
  cert_id: String,
  cache: AriCache,
) -> Result(Nil, StorageError) {
  let path = ari_cache_path(storage_path)
  use _ <- result.try(ensure_directory(storage_path))
  let contents =
    json.to_string(
      json.object([
        #("cert_id", json.string(cert_id)),
        #("next_check", json.int(timestamp_to_unix(cache.next_check))),
        #("window_start", json.int(timestamp_to_unix(cache.window_start))),
        #("window_end", json.int(timestamp_to_unix(cache.window_end))),
        #("renewal_at", json.int(timestamp_to_unix(cache.renewal_at))),
      ]),
    )
  simplifile.write(path, contents)
  |> result.map_error(FileError)
}
