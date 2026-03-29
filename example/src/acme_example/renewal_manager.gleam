import acme_example/acme_client
import acme_example/certificate
import acme_example/challenge_store
import acme_example/storage
import acumen
import acumen/fetch_renewal_info
import acumen/renewal_info.{type RenewalInfo}
import gleam/erlang/atom
import gleam/erlang/process
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/io
import gleam/option.{type Option}
import gleam/order
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/duration
import gleam/time/timestamp.{type Timestamp}
import mist
import wisp
import wisp/wisp_mist

const max_renewal_retries = 10

const default_ari_retry_after_hours = 6

pub type Message {
  Initialize
  CheckRenewalInfo
  Renew
  MistDown(process.Down)
}

type ScheduledRenewal {
  ScheduledRenewal(
    timer: process.Timer,
    window_start: Timestamp,
    window_end: Timestamp,
    renewal_at: Timestamp,
  )
}

type State {
  State(
    self: process.Subject(Message),
    config: acme_client.Config,
    store: process.Subject(challenge_store.Message),
    mist_server: Option(#(process.Pid, process.Monitor)),
    retry_attempt: Int,
    renewal_timer: Option(ScheduledRenewal),
  )
}

type AriResult {
  AriResult(
    cert_id: String,
    renewal_info: RenewalInfo,
    retry_after: duration.Duration,
  )
}

pub fn child(
  config: acme_client.Config,
  store_name: process.Name(challenge_store.Message),
) -> supervision.ChildSpecification(process.Subject(Message)) {
  let store = process.named_subject(store_name)
  supervision.worker(fn() { start(config, store) })
}

fn start(
  config: acme_client.Config,
  store: process.Subject(challenge_store.Message),
) -> actor.StartResult(process.Subject(Message)) {
  actor.new_with_initialiser(5000, fn(self) {
    let state =
      State(
        self:,
        config:,
        store:,
        mist_server: option.None,
        retry_attempt: 0,
        renewal_timer: option.None,
      )
    process.send(self, Initialize)
    actor.initialised(state)
    |> actor.returning(self)
    |> Ok
  })
  |> actor.on_message(handle_message)
  |> actor.start
}

fn handle_message(state: State, message: Message) -> actor.Next(State, Message) {
  case message {
    Initialize -> handle_initialize(state)
    CheckRenewalInfo -> handle_check_renewal_info(state)
    Renew -> handle_renew(state)
    MistDown(_down) -> handle_mist_down(state)
  }
}

fn handle_check_renewal_info(state: State) -> actor.Next(State, Message) {
  let state = schedule_renewal_cached(state)
  actor.continue(state)
}

fn handle_initialize(state: State) -> actor.Next(State, Message) {
  let #(needs_renewal, status_message) =
    check_certificate(state.config.cert_path)
  io.println("Certificate status: " <> status_message)

  case needs_renewal {
    True -> {
      process.send(state.self, Renew)
      actor.continue(state)
    }
    False -> {
      io.println("Using existing certificate")
      let state = ensure_mist_running(state)
      let state = schedule_renewal_cached(state)
      continue_with_monitor(state)
    }
  }
}

fn handle_renew(state: State) -> actor.Next(State, Message) {
  case state.mist_server {
    option.Some(_) -> {
      io.println("")
      io.println("=== Renewal timer fired ===")
    }
    option.None -> Nil
  }

  io.println("Attempting certificate renewal...")
  case run_acme(state) {
    Ok(Nil) -> {
      io.println("Certificate obtained successfully!")
      io.println("")
      let state = ensure_mist_running(state)
      let state = cancel_renewal_timer(state)
      let state = schedule_renewal(state)
      let state = State(..state, retry_attempt: 0)
      continue_with_monitor(state)
    }
    Error(err) -> handle_renew_error(state, err)
  }
}

fn handle_renew_error(state: State, err: String) -> actor.Next(State, Message) {
  io.println_error("ACME workflow failed: " <> err)
  let attempt = state.retry_attempt
  case attempt >= max_renewal_retries {
    True -> {
      io.println_error(
        "Max renewal retries reached, will try again at next window",
      )
      let state = State(..state, retry_attempt: 0)
      let state = cancel_renewal_timer(state)
      let state = schedule_renewal(state)
      continue_with_monitor(state)
    }
    False -> {
      let next_attempt = attempt + 1
      let backoff_ms = renewal_backoff_ms(attempt)
      io.println(
        "Retrying in "
        <> int.to_string(backoff_ms / 1000)
        <> " seconds (attempt "
        <> int.to_string(next_attempt)
        <> "/"
        <> int.to_string(max_renewal_retries)
        <> ")",
      )
      let state = State(..state, retry_attempt: next_attempt)
      process.send_after(state.self, backoff_ms, Renew)
      continue_with_monitor(state)
    }
  }
}

fn handle_mist_down(state: State) -> actor.Next(State, Message) {
  io.println("HTTPS server process died, restarting...")
  let state = stop_mist(state)
  case start_mist(state) {
    Ok(#(new_state, _monitor)) -> continue_with_monitor(new_state)
    Error(err) -> {
      io.println_error(
        "Failed to restart HTTPS server: " <> string.inspect(err),
      )
      continue_with_monitor(state)
    }
  }
}

fn run_acme(state: State) -> Result(Nil, String) {
  let replaces =
    certificate.read_cert_id(state.config.cert_path)
    |> option.from_result

  acme_client.run(acme_client.Config(..state.config, replaces:), state.store)
  |> result.map_error(fn(err) { string.inspect(err) })
}

fn start_mist(
  state: State,
) -> Result(#(State, process.Monitor), actor.StartError) {
  let handler =
    handle_https_request
    |> wisp_mist.handler(wisp.random_string(64))

  handler
  |> mist.new
  |> mist.bind("0.0.0.0")
  |> mist.port(state.config.https_port)
  |> mist.with_tls(
    certfile: state.config.cert_path,
    keyfile: state.config.key_path,
  )
  |> mist.start
  |> result.map(fn(started) {
    let monitor = process.monitor(started.pid)
    #(
      State(..state, mist_server: option.Some(#(started.pid, monitor))),
      monitor,
    )
  })
}

fn stop_mist(state: State) -> State {
  case state.mist_server {
    option.Some(#(pid, monitor)) -> {
      process.send_abnormal_exit(pid, atom.create("shutdown"))
      let selector =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_down) { Nil })
      let _ = process.selector_receive(from: selector, within: 5000)
      State(..state, mist_server: option.None)
    }
    option.None -> state
  }
}

fn ensure_mist_running(state: State) -> State {
  let is_restart = option.is_some(state.mist_server)
  let state = stop_mist(state)
  case start_mist(state) {
    Ok(#(new_state, _monitor)) -> {
      case is_restart {
        True -> Nil
        False ->
          io.println(
            "HTTPS server running on port "
            <> int.to_string(state.config.https_port),
          )
      }
      new_state
    }
    Error(err) -> {
      let action = case is_restart {
        True -> "restart"
        False -> "start"
      }
      io.println_error(
        "Failed to " <> action <> " HTTPS server: " <> string.inspect(err),
      )
      state
    }
  }
}

fn continue_with_monitor(state: State) -> actor.Next(State, Message) {
  case state.mist_server {
    option.Some(#(_pid, monitor)) -> {
      let selector =
        process.new_selector()
        |> process.select(state.self)
        |> process.select_specific_monitor(monitor, MistDown)
      actor.continue(state)
      |> actor.with_selector(selector)
    }
    option.None -> actor.continue(state)
  }
}

fn handle_https_request(req: wisp.Request) -> wisp.Response {
  use <- wisp.log_request(req)
  wisp.ok()
  |> wisp.string_body("Hello from TLS")
}

fn schedule_renewal_cached(state: State) -> State {
  let now = timestamp.system_time()
  let cached =
    certificate.read_cert_id(state.config.cert_path)
    |> result.replace_error(Nil)
    |> result.try(fn(cert_id) {
      storage.load_ari_cache(state.config.storage_path, cert_id)
    })
  case cached {
    Ok(cache) ->
      case timestamp.compare(now, cache.renewal_at) {
        order.Gt | order.Eq -> {
          io.println(
            "Scheduled renewal time reached, triggering renewal (cached)",
          )
          process.send(state.self, Renew)
          state
        }
        order.Lt -> {
          case timestamp.compare(now, cache.next_check) {
            order.Lt -> {
              let #(state, renewal_at) =
                ensure_renewal_timer(
                  state,
                  cache.window_start,
                  cache.window_end,
                )
              log_ari_schedule(
                window_start: cache.window_start,
                window_end: cache.window_end,
                renewal_at:,
                next_check: cache.next_check,
              )
              let delay =
                timestamp.difference(now, cache.next_check)
                |> duration.to_milliseconds
              process.send_after(state.self, delay, CheckRenewalInfo)
              state
            }
            _ -> schedule_renewal(state)
          }
        }
      }
    Error(_) -> schedule_renewal(state)
  }
}

fn schedule_renewal(state: State) -> State {
  io.println("Fetching ACME Renewal Information (ARI)...")
  case fetch_ari(state.config.directory_url, state.config.cert_path) {
    Ok(ari) -> {
      let now = timestamp.system_time()
      let window = ari.renewal_info.suggested_window
      let #(state, renewal_at) =
        ensure_renewal_timer(state, window.start, window.end)
      case timestamp.compare(now, renewal_at) {
        order.Gt | order.Eq -> {
          io.println("Scheduled renewal time reached, triggering renewal")
          process.send(state.self, Renew)
          state
        }
        order.Lt -> {
          let delay_ms = duration.to_milliseconds(ari.retry_after)
          let next_check = timestamp.add(now, ari.retry_after)
          log_ari_schedule(
            window_start: window.start,
            window_end: window.end,
            renewal_at:,
            next_check:,
          )

          let result =
            storage.save_ari_cache(
              state.config.storage_path,
              ari.cert_id,
              storage.AriCache(
                next_check:,
                window_start: window.start,
                window_end: window.end,
                renewal_at:,
              ),
            )
          case result {
            Ok(_) -> Nil
            Error(_) -> io.println("Warning: failed to save ARI cache to disk")
          }

          process.send_after(state.self, delay_ms, CheckRenewalInfo)
          state
        }
      }
    }
    Error(_) -> {
      io.println("Renewal info not available, using local calculation")
      case compute_renewal_delay(state.config.cert_path) {
        Ok(delay) -> {
          let delay_ms = duration.to_milliseconds(delay)
          io.println(
            "Next renewal check in "
            <> int.to_string(delay_ms / 1000 / 60)
            <> " minutes",
          )
          process.send_after(state.self, delay_ms, Renew)
          state
        }
        Error(_) -> {
          io.println("Cannot read certificate, triggering renewal")
          process.send(state.self, Renew)
          state
        }
      }
    }
  }
}

fn fetch_ari(directory_url: String, cert_path: String) -> Result(AriResult, Nil) {
  use req <- result.try(request.to(directory_url))
  use resp <- result.try(
    httpc.send(req)
    |> result.replace_error(Nil),
  )
  use directory <- result.try(
    acumen.directory(resp)
    |> result.replace_error(Nil),
  )
  use cert_id <- result.try(
    certificate.read_cert_id(cert_path)
    |> result.replace_error(Nil),
  )
  use ari_req <- result.try(
    fetch_renewal_info.build(directory, cert_id)
    |> result.replace_error(Nil),
  )
  use ari_resp <- result.try(
    httpc.send(ari_req)
    |> result.replace_error(Nil),
  )
  let retry_after = case acumen.retry_after(ari_resp) {
    Ok(acumen.RetryAfterSeconds(seconds)) -> duration.seconds(seconds)
    Ok(acumen.RetryAfterTimestamp(ts)) ->
      timestamp.difference(timestamp.system_time(), ts)
    _ -> duration.hours(default_ari_retry_after_hours)
  }

  fetch_renewal_info.response(ari_resp)
  |> result.replace_error(Nil)
  |> result.map(AriResult(cert_id, _, retry_after))
}

fn random_time_in_window(start: Timestamp, end: Timestamp) -> Timestamp {
  let #(start_s, _) = timestamp.to_unix_seconds_and_nanoseconds(start)
  let #(end_s, _) = timestamp.to_unix_seconds_and_nanoseconds(end)
  let range = int.max(end_s - start_s, 1)
  timestamp.from_unix_seconds(start_s + int.random(range))
}

fn ensure_renewal_timer(
  state: State,
  window_start: Timestamp,
  window_end: Timestamp,
) -> #(State, Timestamp) {
  case state.renewal_timer {
    option.Some(scheduled) -> {
      let start_matches =
        timestamp.compare(scheduled.window_start, window_start) == order.Eq
      let end_matches =
        timestamp.compare(scheduled.window_end, window_end) == order.Eq
      case start_matches && end_matches {
        True -> #(state, scheduled.renewal_at)
        False -> {
          let _ = process.cancel_timer(scheduled.timer)
          set_renewal_timer(state, window_start, window_end)
        }
      }
    }
    option.None -> set_renewal_timer(state, window_start, window_end)
  }
}

fn set_renewal_timer(
  state: State,
  window_start: Timestamp,
  window_end: Timestamp,
) -> #(State, Timestamp) {
  let renewal_at = random_time_in_window(window_start, window_end)
  let now = timestamp.system_time()
  let delay_ms =
    timestamp.difference(now, renewal_at)
    |> duration.to_milliseconds
    |> int.max(0)
  let timer = process.send_after(state.self, delay_ms, Renew)
  let state =
    State(
      ..state,
      renewal_timer: option.Some(ScheduledRenewal(
        timer:,
        window_start:,
        window_end:,
        renewal_at:,
      )),
    )
  #(state, renewal_at)
}

fn cancel_renewal_timer(state: State) -> State {
  case state.renewal_timer {
    option.Some(scheduled) -> {
      let _ = process.cancel_timer(scheduled.timer)
      State(..state, renewal_timer: option.None)
    }
    option.None -> state
  }
}

fn log_ari_schedule(
  window_start window_start: Timestamp,
  window_end window_end: Timestamp,
  renewal_at renewal_at: Timestamp,
  next_check next_check: Timestamp,
) -> Nil {
  let start = timestamp.to_rfc3339(window_start, calendar.utc_offset)
  let end = timestamp.to_rfc3339(window_end, calendar.utc_offset)
  io.println("Renewal info: suggested window " <> start <> " to " <> end)
  io.println(
    "Renewal scheduled at "
    <> timestamp.to_rfc3339(renewal_at, calendar.utc_offset),
  )
  io.println(
    "Next ARI check at "
    <> timestamp.to_rfc3339(next_check, calendar.utc_offset),
  )
}

fn compute_renewal_delay(cert_path: String) -> Result(duration.Duration, Nil) {
  let now = timestamp.system_time()
  certificate.time_until_renewal(cert_path, now)
  |> result.replace_error(Nil)
}

fn renewal_backoff_ms(attempt: Int) -> Int {
  let base_ms = 60_000
  let max_ms = 3_600_000
  int.min(base_ms * int.bitwise_shift_left(1, attempt), max_ms)
}

fn check_certificate(cert_path: String) -> #(Bool, String) {
  let now = timestamp.system_time()
  let status = certificate.check_certificate_status(cert_path, now)
  case status {
    certificate.Missing -> #(True, "No existing certificate found")
    certificate.Invalid(certificate.NotYetValid(not_before)) -> #(
      True,
      "Certificate is not valid until "
        <> timestamp.to_rfc3339(not_before, calendar.utc_offset),
    )
    certificate.Invalid(_) -> #(True, "Existing certificate is invalid")
    certificate.Expired(expired_at) -> #(
      True,
      "Certificate expired on "
        <> timestamp.to_rfc3339(expired_at, calendar.utc_offset),
    )
    certificate.ExpiresSoon(expires_at, days_remaining, grace_period) -> #(
      True,
      "Certificate expires on "
        <> timestamp.to_rfc3339(expires_at, calendar.utc_offset)
        <> " ("
        <> int.to_string(days_remaining)
        <> " days remaining, within "
        <> int.to_string(grace_period)
        <> "-day renewal window)",
    )
    certificate.Valid(expires_at) -> #(
      False,
      "Certificate valid until "
        <> timestamp.to_rfc3339(expires_at, calendar.utc_offset),
    )
  }
}
