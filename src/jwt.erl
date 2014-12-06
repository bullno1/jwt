-module(jwt).
-export([issue_token/2, parse_token/2]).
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-type signing_algorithm() :: none
                           | {'HS256', Secret :: binary()}
                           | {Name :: atom(), SigFun :: fun((Payload :: binary(), Opts) -> binary()), Opts}.
-type claim_set() :: jsx:json_term().

-spec issue_token(claim_set(), signing_algorithm()) -> binary().
issue_token(ClaimSet, SigAlg) ->
	EncodedClaimSet = encode(ClaimSet),
	EncodedHeader = encode(#{typ => <<"JWT">>, alg => algorithm_name(SigAlg)}),
	Payload = <<EncodedHeader/binary, $., EncodedClaimSet/binary>>,
	Signature = sign(Payload, SigAlg),
	<<Payload/binary, $., Signature/binary>>.

-spec parse_token(binary(), [signing_algorithm()]) -> {ok, claim_set()} | {error, Error} when
	Error :: malformed_token | invalid_signature | unsupported_algorithm.
parse_token(Token, SigAlgs) ->
	case binary:split(Token, <<".">>, [global]) of
		[EncodedHeader, EncodedClaimSet, Signature] ->
			parse_token1(EncodedHeader, EncodedClaimSet, Signature, SigAlgs);
		_ ->
			{error, malformed_token}
	end.

parse_token1(EncodedHeader, EncodedClaimSet, Signature, SigAlgs) ->
	case verify_token(EncodedHeader, EncodedClaimSet, Signature, SigAlgs) of
		ok ->
			case decode(EncodedClaimSet) of
				{ok, ClaimSet} -> {ok, ClaimSet};
				error -> {error, malformed_token}
			end;
		{error, _} = Err -> Err
	end.

verify_token(EncodedHeader, EncodedClaimSet, Signature, SigAlgs) ->
	case decode(EncodedHeader) of
		{ok, Header} ->
			case proplists:get_value(<<"alg">>, Header) of
				undefined -> {error, malformed_token};
				BinAlgName ->
					try binary_to_existing_atom(BinAlgName, latin1) of
						AlgName ->
							case find_algorithm(AlgName, SigAlgs) of
								{ok, Alg} ->
									Payload = <<EncodedHeader/binary, $., EncodedClaimSet/binary>>,
									ExpectedSignature = sign(Payload, Alg),
									case compare(ExpectedSignature, Signature) of
										true -> ok;
										false -> {error, invalid_signature}
									end;
								error ->
									{error, unsupported_algorithm}
							end
					catch
						error:badarg ->
							{error, unsupported_algorithm}
					end
			end;
		error ->
			{error, malformed_token}
	end.

find_algorithm(none, Algs) ->
	case lists:member(none, Algs) of
		true -> {ok, none};
		false -> error
	end;
find_algorithm(Name, Algs) ->
	case proplists:lookup(Name, Algs) of
		none -> error;
		Result -> {ok, Result}
	end.

encode(JsonTerm) -> base64url:encode(jsx:encode(JsonTerm)).

decode(Base64Json) ->
	try jsx:decode(base64url:decode(Base64Json)) of
		Result -> {ok, Result}
	catch
		error:badarg -> error
	end.

algorithm_name(none) -> none;
algorithm_name({'HS256', _}) -> 'HS256';
algorithm_name({Name, _, _}) -> Name.

sign(_, none) -> <<>>;
sign(Data, {'HS256', Secret}) -> base64url:encode(crypto:hmac(sha256, Secret, Data));
sign(Data, {_, SigFun, Opts}) -> base64url:encode(SigFun(Data, Opts)).

% Compare two binaries in constant time
compare(Bin1, Bin2) ->
	case byte_size(Bin1) =:= byte_size(Bin2) of
		true -> compare1(Bin1, Bin2, 0);
		false -> false
	end.

compare1(<<>>, <<>>, Acc) -> Acc =:= 0;
compare1(<<Byte1:8, Rest1/binary>>, <<Byte2:8, Rest2/binary>>, Acc) ->
	compare1(Rest1, Rest2, (Byte1 bxor Byte2) bor Acc).

-ifdef(TEST).
issue_token_test_() ->
	%value taken from jwt.io
	?_assertEqual(
	   issue_token([{sub, 1234567890}, {name, <<"John Doe">>}, {admin, true}], {'HS256', <<"secret">>}),
	   <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.eoaDVGTClRdfxUZXiPs3f8FmJDkDE_VCQFXqKxpLsts">>
	).

parse_token_test_() ->
	ClaimSet = [{<<"sub">>, 1234567890}, {<<"name">>, <<"John Doe">>}, {<<"admin">>, true}],
	HS256 = {'HS256', <<"secret">>},
	HS256_2 = {'HS256', <<"secret2">>},
	HS512 = {'HS512', fun(Data, Secret) -> crypto:hmac(sha512, Secret, Data) end, <<"secret">>},
	[?_assertEqual(
		parse_token(issue_token(ClaimSet, HS256), [HS256]),
		{ok, ClaimSet})
	,?_assertEqual(
		parse_token(issue_token(ClaimSet, none), [none]),
		{ok, ClaimSet})
	,?_assertEqual(
		parse_token(issue_token(ClaimSet, HS256), [none, HS256]),
		{ok, ClaimSet})
	,?_assertEqual(
		parse_token(issue_token(ClaimSet, none), [none, HS256]),
		{ok, ClaimSet})
	,?_assertEqual(
		parse_token(issue_token(ClaimSet, HS512), [HS512, HS256]),
		{ok, ClaimSet})
	,?_assertEqual(
		parse_token(issue_token(ClaimSet, HS256_2), [HS256]),
		{error, invalid_signature})
	,?_assertEqual(
		parse_token(issue_token(ClaimSet, none), [HS256]),
		{error, unsupported_algorithm})
	,?_assertEqual(
		parse_token(issue_token(ClaimSet, HS256), [none, HS512]),
		{error, unsupported_algorithm})
	,?_assertEqual(
		parse_token(issue_token(ClaimSet, HS512), [HS256]),
		{error, unsupported_algorithm})
	,?_assertEqual(
		parse_token(issue_token(ClaimSet, HS512), [HS256]),
		{error, unsupported_algorithm})
	].

malformd_token_test_() ->
	[?_assertEqual(
		parse_token(<<"abc">>, [none]),
		{error, malformed_token})
	,?_assertEqual(
		parse_token(<<(base64url:encode(<<"{">>))/binary, "..">>, none),
		{error, malformed_token})
	,?_assertEqual(
		parse_token(<<(base64url:encode(<<"{}">>))/binary, "..">>, none),
		{error, malformed_token})
	,?_assertEqual(
		parse_token(<<(base64url:encode(<<"{\"alg\":\"asdf\"}">>))/binary, "..">>, [none]),
		{error, unsupported_algorithm})
	].

-endif.
