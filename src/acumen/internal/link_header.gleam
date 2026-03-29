import acumen/url
import gleam/list
import gleam/result
import gleam/string
import splitter

type LinkHeader {
  LinkHeader(uri: url.Url, parameters: List(#(String, String)))
}

pub fn find_by_rel(header: String, rel rel: String) -> Result(url.Url, Nil) {
  use links <- result.try(parse_link_header(header))
  links
  |> list.find(fn(link) { has_rel(link.parameters, rel) })
  |> result.map(fn(link) { link.uri })
}

fn has_rel(parameters: List(#(String, String)), rel: String) -> Bool {
  list.any(parameters, fn(param) {
    param.0 == "rel" && list.contains(string.split(param.1, " "), rel)
  })
}

fn parse_link_header(header: String) -> Result(List(LinkHeader), Nil) {
  let sep = splitter.new([",", "\"", "\\"])
  header
  |> split_link_values(sep, _, [])
  |> list.try_map(parse_link_value)
}

fn split_link_values(
  sep: splitter.Splitter,
  remaining: String,
  acc: List(String),
) -> List(String) {
  case string.trim(remaining) {
    "" -> list.reverse(acc)
    "," <> rest -> split_link_values(sep, rest, acc)
    trimmed -> {
      case string.split_once(trimmed, ">") {
        Error(_) -> list.reverse([trimmed, ..acc])
        Ok(#(before_close, after_close)) ->
          find_link_separator(sep, after_close, before_close <> ">", acc, False)
      }
    }
  }
}

fn find_link_separator(
  sep: splitter.Splitter,
  remaining: String,
  current: String,
  acc: List(String),
  in_quote: Bool,
) -> List(String) {
  case splitter.split(sep, remaining) {
    #(rest, "", "") -> {
      case string.trim(current <> rest) {
        "" -> list.reverse(acc)
        trimmed -> list.reverse([trimmed, ..acc])
      }
    }

    #(before, "\\", rest) if in_quote -> {
      case string.pop_grapheme(rest) {
        Ok(#(escaped, rest)) ->
          find_link_separator(
            sep,
            rest,
            current <> before <> "\\" <> escaped,
            acc,
            in_quote,
          )
        Error(_) ->
          find_link_separator(
            sep,
            rest,
            current <> before <> "\\",
            acc,
            in_quote,
          )
      }
    }

    #(before, "\\", rest) ->
      find_link_separator(sep, rest, current <> before <> "\\", acc, in_quote)

    #(before, "\"", rest) ->
      find_link_separator(sep, rest, current <> before <> "\"", acc, !in_quote)

    #(before, ",", rest) if in_quote ->
      find_link_separator(sep, rest, current <> before <> ",", acc, in_quote)

    #(before, ",", rest) ->
      split_link_values(sep, rest, [string.trim(current <> before), ..acc])

    #(before, delim, rest) ->
      find_link_separator(sep, rest, current <> before <> delim, acc, in_quote)
  }
}

fn parse_link_value(link_value: String) -> Result(LinkHeader, Nil) {
  case string.trim_start(link_value) {
    "<" <> after_open -> {
      use #(uri_string, params) <- result.try(string.split_once(after_open, ">"))
      use parsed_url <- result.try(url.from_string(uri_string))

      parse_link_parameters(params, [])
      |> result.map(LinkHeader(parsed_url, _))
    }
    _ -> Error(Nil)
  }
}

fn parse_link_parameters(
  header: String,
  parameters: List(#(String, String)),
) -> Result(List(#(String, String)), Nil) {
  case header {
    "" -> Ok(list.reverse(parameters))

    " " <> rest | "\t" <> rest -> parse_link_parameters(rest, parameters)

    ";" <> rest -> parse_link_parameters_after_semicolon(rest, parameters)

    _ -> Error(Nil)
  }
}

fn parse_link_parameters_after_semicolon(
  header: String,
  parameters: List(#(String, String)),
) -> Result(List(#(String, String)), Nil) {
  case header {
    "" -> Error(Nil)

    " " <> rest | "\t" <> rest ->
      parse_link_parameters_after_semicolon(rest, parameters)

    _ -> {
      case string.pop_grapheme(header) {
        Error(_) -> Error(Nil)
        Ok(#(grapheme, rest)) -> {
          let name = string.lowercase(grapheme)
          use #(parameter, rest) <- result.try(parse_link_parameter_name(
            rest,
            name,
          ))
          parse_link_parameters(rest, [parameter, ..parameters])
        }
      }
    }
  }
}

fn parse_link_parameter_name(
  header: String,
  name: String,
) -> Result(#(#(String, String), String), Nil) {
  let sep = splitter.new(["=", " ", "\t", ";"])
  case splitter.split(sep, header) {
    #(prefix, "", "") -> Ok(#(#(name <> string.lowercase(prefix), ""), ""))

    #(prefix, "=", rest) ->
      parse_parameter_value(
        string.trim_start(rest),
        name <> string.lowercase(prefix),
      )

    #(prefix, " ", rest) | #(prefix, "\t", rest) ->
      parse_link_parameter_after_name(
        string.trim_start(rest),
        name <> string.lowercase(prefix),
      )

    #(prefix, ";", rest) ->
      Ok(#(#(name <> string.lowercase(prefix), ""), ";" <> rest))

    #(prefix, _, rest) -> Ok(#(#(name <> string.lowercase(prefix), ""), rest))
  }
}

fn parse_link_parameter_after_name(
  header: String,
  name: String,
) -> Result(#(#(String, String), String), Nil) {
  case header {
    "" -> Ok(#(#(name, ""), ""))
    "=" <> rest -> parse_parameter_value(string.trim_start(rest), name)
    _ -> Ok(#(#(name, ""), header))
  }
}

fn parse_parameter_value(
  header: String,
  name: String,
) -> Result(#(#(String, String), String), Nil) {
  case header {
    "" -> Error(Nil)
    "\"" <> rest -> parse_quoted_value(rest, name, "")
    _ -> {
      case string.pop_grapheme(header) {
        Error(_) -> Error(Nil)
        Ok(#(grapheme, rest)) -> Ok(parse_unquoted_value(rest, name, grapheme))
      }
    }
  }
}

fn parse_quoted_value(
  header: String,
  name: String,
  value: String,
) -> Result(#(#(String, String), String), Nil) {
  case string.pop_grapheme(header) {
    Error(Nil) -> Error(Nil)
    Ok(#("\"", rest)) -> Ok(#(#(name, value), rest))
    Ok(#("\\", rest)) -> {
      case string.pop_grapheme(rest) {
        Error(Nil) -> Error(Nil)
        Ok(#(grapheme, rest)) ->
          parse_quoted_value(rest, name, value <> grapheme)
      }
    }
    Ok(#(grapheme, rest)) -> parse_quoted_value(rest, name, value <> grapheme)
  }
}

fn parse_unquoted_value(
  header: String,
  name: String,
  value: String,
) -> #(#(String, String), String) {
  case header {
    "" -> #(#(name, value), header)

    ";" <> _ -> #(#(name, value), header)
    " " <> rest | "\t" <> rest -> #(#(name, value), rest)

    _ -> {
      case string.pop_grapheme(header) {
        Error(_) -> #(#(name, value), "")
        Ok(#(grapheme, rest)) ->
          parse_unquoted_value(rest, name, value <> grapheme)
      }
    }
  }
}
