-module(acme_example_ffi).
-export([get_line/1, lookup_txt/1]).

get_line(Prompt) ->
    case io:get_line(Prompt) of
        eof -> <<>>;
        {error, _} -> <<>>;
        Data when is_binary(Data) -> Data;
        Data when is_list(Data) -> unicode:characters_to_binary(Data)
    end.

lookup_txt(Domain) ->
    %% Query Google's public DNS directly to bypass local resolver caching
    Opts = [{nameservers, [{{8, 8, 8, 8}, 53}]}],
    Records = inet_res:lookup(binary_to_list(Domain), in, txt, Opts),
    [unicode:characters_to_binary(lists:flatten(Strings))
     || Strings <- Records].
