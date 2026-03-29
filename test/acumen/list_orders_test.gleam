import acumen
import acumen/list_orders
import acumen/url
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/option
import support/fixtures

pub fn build_creates_post_as_get_request_test() {
  let ctx = fixtures.test_context()
  let key = fixtures.test_registered_key()
  let assert Ok(url) = url.from_string("https://example.com/acct/123/orders")

  let assert Ok(req) = list_orders.build(url, ctx, key)

  assert req.method == http.Post
  assert req.host == "example.com"
  assert req.path == "/acct/123/orders"

  let assert Ok(content_type) = request.get_header(req, "content-type")
  assert content_type == "application/jose+json"
}

pub fn response_parses_orders_list_test() {
  let body =
    json.object([
      #(
        "orders",
        json.array(
          [
            "https://example.com/order/1",
            "https://example.com/order/2",
            "https://example.com/order/3",
          ],
          json.string,
        ),
      ),
    ])
    |> json.to_string
  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(orders_list) = list_orders.response(resp)

  let assert Ok(url1) = url.from_string("https://example.com/order/1")
  let assert Ok(url2) = url.from_string("https://example.com/order/2")
  let assert Ok(url3) = url.from_string("https://example.com/order/3")
  assert orders_list.orders == [url1, url2, url3]
  assert orders_list.next == option.None
}

pub fn response_parses_empty_orders_test() {
  let body =
    json.object([#("orders", json.array([], json.string))])
    |> json.to_string
  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(orders_list) = list_orders.response(resp)

  assert orders_list.orders == []
  assert orders_list.next == option.None
}

pub fn response_parses_next_link_test() {
  let body =
    json.object([
      #("orders", json.array(["https://example.com/order/1"], json.string)),
    ])
    |> json.to_string
  let resp =
    fixtures.nonce_response(200, "new-nonce", body)
    |> response.set_header(
      "link",
      "<https://example.com/acct/123/orders?cursor=abc>; rel=\"next\"",
    )

  let assert Ok(orders_list) = list_orders.response(resp)

  let assert Ok(next_url) =
    url.from_string("https://example.com/acct/123/orders?cursor=abc")
  assert orders_list.next == option.Some(next_url)
}

pub fn response_parses_next_link_from_multiple_link_headers_test() {
  let body =
    json.object([
      #("orders", json.array(["https://example.com/order/1"], json.string)),
    ])
    |> json.to_string
  let resp =
    fixtures.nonce_response(200, "new-nonce", body)
    |> response.prepend_header(
      "link",
      "<https://example.com/acct/123/orders?cursor=next>; rel=\"next\"",
    )
    |> response.prepend_header(
      "link",
      "<https://example.com/acct/123/orders?cursor=prev>; rel=\"prev\"",
    )

  let assert Ok(orders_list) = list_orders.response(resp)

  let assert Ok(next_url) =
    url.from_string("https://example.com/acct/123/orders?cursor=next")
  assert orders_list.next == option.Some(next_url)
}

pub fn response_without_next_link_test() {
  let body =
    json.object([
      #("orders", json.array(["https://example.com/order/1"], json.string)),
    ])
    |> json.to_string
  let resp = fixtures.nonce_response(200, "new-nonce", body)

  let assert Ok(orders_list) = list_orders.response(resp)

  assert orders_list.next == option.None
}

pub fn response_rejects_unexpected_status_test() {
  let resp = fixtures.nonce_response(404, "new-nonce", "{}")

  let assert Error(acumen.InvalidResponse(_)) = list_orders.response(resp)
}

pub fn response_rejects_malformed_json_body_test() {
  let resp = fixtures.nonce_response(200, "new-nonce", "not json")

  let assert Error(acumen.JsonParseError(_)) = list_orders.response(resp)
}
