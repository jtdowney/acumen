import acumen/renewal_info
import gleam/bool
import gleam/int
import gleam/list
import gleam/result
import gleam/time/duration
import gleam/time/timestamp.{type Timestamp}
import kryptos/x509
import kryptos/x509/certificate as x509_certificate
import simplifile

// CA/B Forum guidelines state "For the purpose of calculations, a day is measured as 86,400 seconds."
// https://cabforum.org/working-groups/server/baseline-requirements/requirements/#632-certificate-operational-periods-and-key-pair-usage-periods
const seconds_per_day = 86_400

const min_grace_period_days = 3

pub type CertificateError {
  FileReadError(simplifile.FileError)
  CertificateParseError(x509_certificate.CertificateError)
  EmptyCertificateChain
  CertificateIdError
  NotYetValid(not_before: Timestamp)
}

pub type CertificateStatus {
  Valid(expires_at: Timestamp)
  ExpiresSoon(expires_at: Timestamp, days_remaining: Int, grace_period: Int)
  Expired(expired_at: Timestamp)
  Missing
  Invalid(CertificateError)
}

fn read_certificate_validity(
  path: String,
) -> Result(x509.Validity, CertificateError) {
  use pem <- result.try(
    simplifile.read(path)
    |> result.map_error(FileReadError),
  )
  use certs <- result.try(
    x509_certificate.from_pem(pem)
    |> result.map_error(CertificateParseError),
  )

  list.first(certs)
  |> result.replace_error(EmptyCertificateChain)
  |> result.map(x509_certificate.validity)
}

pub fn check_certificate_status(
  path: String,
  now: Timestamp,
) -> CertificateStatus {
  let file_exists = simplifile.is_file(path) |> result.unwrap(False)
  use <- bool.guard(when: !file_exists, return: Missing)

  case read_certificate_validity(path) {
    Error(err) -> Invalid(err)
    Ok(validity) -> classify_validity(validity, now)
  }
}

fn classify_validity(
  validity: x509.Validity,
  now: Timestamp,
) -> CertificateStatus {
  let x509.Validity(not_before:, not_after: expires_at) = validity
  let now_seconds = to_seconds(now)
  let not_before_seconds = to_seconds(not_before)
  let expires_seconds = to_seconds(expires_at)

  use <- bool.guard(
    when: now_seconds < not_before_seconds,
    return: Invalid(NotYetValid(not_before)),
  )

  use <- bool.guard(
    when: now_seconds >= expires_seconds,
    return: Expired(expired_at: expires_at),
  )

  let grace_period_seconds = grace_period(not_before_seconds, expires_seconds)
  let remaining_seconds = expires_seconds - now_seconds

  case remaining_seconds <= grace_period_seconds {
    True -> {
      let days_remaining = remaining_seconds / seconds_per_day
      let grace_period_days = grace_period_seconds / seconds_per_day
      ExpiresSoon(expires_at:, days_remaining:, grace_period: grace_period_days)
    }
    False -> Valid(expires_at:)
  }
}

pub fn time_until_renewal(
  path: String,
  now: Timestamp,
) -> Result(duration.Duration, CertificateError) {
  use validity <- result.try(read_certificate_validity(path))
  let x509.Validity(not_before:, not_after: expires_at) = validity
  let now_seconds = to_seconds(now)
  let not_before_seconds = to_seconds(not_before)
  let expires_seconds = to_seconds(expires_at)

  let grace_period_seconds = grace_period(not_before_seconds, expires_seconds)
  let renewal_at_seconds = expires_seconds - grace_period_seconds
  let delay_seconds = int.max(renewal_at_seconds - now_seconds, 0)

  Ok(duration.seconds(delay_seconds))
}

fn to_seconds(ts: Timestamp) -> Int {
  let #(seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(ts)
  seconds
}

fn grace_period(not_before_seconds: Int, expires_seconds: Int) -> Int {
  let total_lifetime_seconds = expires_seconds - not_before_seconds
  int.max(total_lifetime_seconds / 3, min_grace_period_days * seconds_per_day)
}

pub fn cert_id_from_pem(pem: String) -> Result(String, CertificateError) {
  use certs <- result.try(
    x509_certificate.from_pem(pem)
    |> result.map_error(CertificateParseError),
  )
  use cert <- result.try(
    list.first(certs)
    |> result.replace_error(EmptyCertificateChain),
  )
  renewal_info.cert_id_from_certificate(cert)
  |> result.replace_error(CertificateIdError)
}

pub fn read_cert_id(path: String) -> Result(String, CertificateError) {
  use pem <- result.try(
    simplifile.read(path)
    |> result.map_error(FileReadError),
  )
  cert_id_from_pem(pem)
}
