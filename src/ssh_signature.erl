-module(ssh_signature).

-compile({nowarn_deprecated_function, {public_key, ssh_encode, 2}}).
-compile({nowarn_deprecated_function, {public_key, ssh_decode, 2}}).

-dialyzer([
    {no_improper_lists, split/1},
    {no_match, priv_to_public/1}
]).

-include_lib("public_key/include/public_key.hrl").

-export([sign/3, sign/4]).
-export([verify/2]).

-export_type([namespace/0, hash_algorithm/0]).

-define(MAGIC_PREAMBLE, "SSHSIG").
-define(SIG_VERSION, 16#01).
-define(UINT32(X), (X):32 / unsigned - big - integer).
-define(STRING(X), ?UINT32(size(X)), (X) / binary).
-define(BEGIN, "-----BEGIN SSH SIGNATURE-----").
-define(END, "-----END SSH SIGNATURE-----").

-type namespace() :: unicode:chardata().
-type hash_algorithm() :: sha256 | sha512.

%% @equiv sign(Data, Key, NS, #{})
sign(Data, Key, NS) -> sign(Data, Key, NS, #{}).

%% @doc Sign `Data' using SSH signature format with `Key'.
%%
%% The `NS' must be not empty.
%%
%% == Options ==
%%
%% <ul>
%%      <li>`hash' - hash algorithm used on input data. Can be either `sha256'
%%      or `sha512'. Defaults to `sha512'.</li>
%% </ul>
%% @end
-spec sign(binary(), public_key:private_key(), namespace(), Opts) ->
    unicode:chardata()
when
    Opts :: #{
        hash => hash_algorithm()
    }.
sign(Data, Key, NS, Opts) ->
    NS0 = iolist_to_binary(NS),
    case NS0 of
        <<>> -> error({badarg, empty_namespace});
        _ -> ok
    end,
    Algo = maps:get(hash, Opts, sha512),
    R = <<"">>,
    Signature = public_key:sign(body(Data, NS, R, Algo), Algo, Key),
    SigType = sig_type(Key, Algo),
    Sig = <<?STRING(SigType), ?STRING(Signature)>>,
    EncPub = encode(priv_to_public(Key)),
    Result =
        <<?MAGIC_PREAMBLE, ?UINT32(?SIG_VERSION), ?STRING(EncPub), ?STRING(NS0),
            ?STRING(R), ?STRING(atom_to_binary(Algo, utf8)), ?STRING(Sig)>>,
    iolist_to_binary([?BEGIN, $\n, split(base64:encode(Result)), $\n, ?END]).

%% @doc Verify `Signature' of `Data'.
%%
%% Notice that this function do not check authenticity of the provided key. That
%% is left to the user to check whether key used for signing match the
%% requirements.
%%
%% @end
-spec verify(binary(), unicode:chardata()) -> {ok, Result} | {error, term()} when
    Result :: #{
        ns => namespace(),
        public_key => public_key:public_key(),
        signature => binary()
    }.
verify(Data, Signature) ->
    Sig0 = string:trim(Signature),
    Sig1 = iolist_to_binary(Sig0),
    Size = byte_size(Sig1) - length(?BEGIN) - length(?END) - 2,
    case Sig1 of
        <<?BEGIN, $\n, Sig2:Size/binary, $\n, ?END>> ->
            Sig3 = base64:decode(Sig2),
            case parse(Sig3) of
                {ok, #{
                    ns := NS,
                    pk := PublicKey,
                    reserved := R,
                    signature := {_, Sig},
                    hash_algorithm := Algo
                }} ->
                    Body = body(Data, NS, R, Algo),
                    case public_key:verify(Body, Algo, Sig, PublicKey) of
                        true ->
                            {ok, #{
                                public_key => PublicKey,
                                ns => NS,
                                signature => Sig
                            }};
                        false ->
                            {error, invalid_signature}
                    end;
                Error ->
                    Error
            end;
        _ ->
            {error, invalid_armour}
    end.

parse(
    <<?MAGIC_PREAMBLE, ?UINT32(Version), ?UINT32(EPS), EncPub:EPS/binary,
        ?UINT32(NSS), NS:NSS/binary, ?UINT32(RS), R:RS/binary, ?UINT32(SAlgoS),
        SAlgo:SAlgoS/binary, ?UINT32(SigDS), ?UINT32(SAS), SigAlgo:SAS/binary,
        ?UINT32(SigS), Sig:SigS/binary>>
) when
    SigDS =:= SAS + 4 + SigS + 4,
    (SAlgo =:= <<"sha256">> orelse SAlgo =:= <<"sha512">>)
->
    PubKey = decode(EncPub),
    Algo =
        case SAlgo of
            <<"sha256">> -> sha256;
            <<"sha512">> -> sha512
        end,
    case type_sig(SigAlgo, PubKey, Algo) of
        true ->
            {ok, #{
                version => Version,
                pk => PubKey,
                ns => NS,
                reserved => R,
                hash_algorithm => Algo,
                signature => {SigAlgo, Sig}
            }};
        _ ->
            {error, type_mismatch}
    end;
parse(_) ->
    {error, invalid_format}.

body(Data, NS, R, Algo) ->
    H = crypto:hash(Algo, Data),
    <<?MAGIC_PREAMBLE, ?STRING(NS), ?STRING(R),
        ?STRING(atom_to_binary(Algo, utf8)), ?STRING(H)>>.

sig_type({ed_pri, Type, _Pub, _Pri}, _Algo) ->
    <<"ssh-", (atom_to_binary(Type, utf8))/binary>>;
sig_type(#'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed25519'}}, _) ->
    <<"ssh-ed25519">>;
sig_type(#'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed448'}}, _) ->
    <<"ssh-ed448">>;
sig_type(#'RSAPrivateKey'{}, sha256) ->
    <<"rsa-sha2-256">>;
sig_type(#'RSAPrivateKey'{}, sha512) ->
    <<"rsa-sha2-512">>.

type_sig(<<"ssh-ed25519">>, {ed_pub, ed25519, _}, _) -> true;
type_sig(<<"ssh-ed448">>, {ed_pub, ed448, _}, _) -> true;
type_sig(<<"rsa-sha2-256">>, #'RSAPublicKey'{}, sha256) -> true;
type_sig(<<"rsa-sha2-512">>, #'RSAPublicKey'{}, sha512) -> true;
type_sig(_, _, _) -> false.

-spec priv_to_public(public_key:private_key()) -> public_key:public_key().
priv_to_public({ed_pri, Type, Pub, _Priv}) ->
    {ed_pub, Type, Pub};
priv_to_public(#'ECPrivateKey'{
    parameters = {namedCurve, Curve},
    publicKey = PK
}) ->
    Type =
        case Curve of
            ?'id-Ed25519' -> ed25519;
            ?'id-Ed448' -> ed448
        end,
    {ed_pub, Type, PK};
priv_to_public(#'RSAPrivateKey'{modulus = Mod, publicExponent = Exp}) ->
    #'RSAPublicKey'{modulus = Mod, publicExponent = Exp};
priv_to_public(Other) ->
    Other.

encode(Key) ->
    case erlang:system_info(otp_release) < "24" of
        true ->
            public_key:ssh_encode(Key, ssh2_pubkey);
        false ->
            ssh_file:encode(Key, ssh2_pubkey)
    end.

decode(Key) ->
    case erlang:system_info(otp_release) < "24" of
        true ->
            public_key:ssh_decode(Key, ssh2_pubkey);
        false ->
            ssh_file:decode(Key, ssh2_pubkey)
    end.

split(<<D:70/binary, Rest/binary>>) ->
    [D, $\n | split(Rest)];
split(Rest) ->
    Rest.
