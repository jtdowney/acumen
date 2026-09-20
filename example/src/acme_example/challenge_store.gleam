import gleam/dict.{type Dict}
import gleam/erlang/process
import gleam/otp/actor
import gleam/otp/supervision
import snag.{type Result}

pub type Message {
  Store(token: String, key_authorization: String)
  Lookup(token: String, reply: process.Subject(Result(String)))
}

pub fn child(
  name: process.Name(Message),
) -> supervision.ChildSpecification(process.Subject(Message)) {
  supervision.worker(fn() { start(name) })
}

pub fn start(
  name: process.Name(Message),
) -> actor.StartResult(process.Subject(Message)) {
  actor.new(dict.new())
  |> actor.named(name)
  |> actor.on_message(handle_message)
  |> actor.start
}

pub fn store(
  store: process.Subject(Message),
  token: String,
  key_authorization: String,
) -> Nil {
  process.send(store, Store(token, key_authorization))
}

pub fn lookup(
  store: process.Subject(Message),
  token: String,
) -> Result(String) {
  process.call(store, waiting: 5000, sending: Lookup(token, _))
}

fn handle_message(
  state: Dict(String, String),
  message: Message,
) -> actor.Next(Dict(String, String), Message) {
  case message {
    Store(token, key_authorization) -> {
      let new_state = dict.insert(state, token, key_authorization)
      actor.continue(new_state)
    }
    Lookup(token, reply) -> {
      process.send(
        reply,
        dict.get(state, token)
          |> snag.replace_error("Challenge token not found"),
      )
      actor.continue(state)
    }
  }
}
