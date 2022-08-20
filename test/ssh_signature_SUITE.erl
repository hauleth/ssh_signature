-module(ssh_signature_SUITE).

-include_lib("public_key/include/public_key.hrl").

% -compile(export_all).

-export([
    all/0,
    groups/0,
    init_per_group/2,
    end_per_group/2,
    can_verify_signed/1,
    signature_can_be_verified_by_openssh/1,
    openssh_can_be_verified/1
]).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

all() ->
    [
        {group, ed25519},
        {group, rsa2048},
        {group, rsa3072},
        {group, rsa4096}
    ].

groups() ->
    Tests = [
        can_verify_signed,
        signature_can_be_verified_by_openssh,
        openssh_can_be_verified
    ],
    Hashes = [sha256, sha512],
    HashTests = [{Hash, [parallel], Tests} || Hash <- Hashes],
    Algos = [ed25519, rsa2048, rsa3072, rsa4096],
    [{Algo, [parallel], HashTests} || Algo <- Algos].

init_per_group(basic, Config) ->
    Config;
init_per_group(GroupName, Config) when
    GroupName =:= sha256; GroupName =:= sha512
->
    [{hash, GroupName} | Config];
init_per_group(GroupName, Config) when
    GroupName =:= ed25519;
    GroupName =:= rsa2048;
    GroupName =:= rsa3072;
    GroupName =:= rsa4096
->
    try
        Key = create_key(GroupName),
        ct:log("Key = ~p.", [Key]),
        [{key, Key}, {algo, GroupName} | Config]
    catch
        _C:_R:_S ->
            {skip, "Algorithm not supported"}
    end.

create_key(ed25519) ->
    public_key:generate_key({namedCurve, ?'id-Ed25519'});
create_key(ed448) ->
    public_key:generate_key({namedCurve, ?'id-Ed448'});
create_key(rsa2048) ->
    public_key:generate_key({rsa, 2048, 3});
create_key(rsa3072) ->
    public_key:generate_key({rsa, 3072, 3});
create_key(rsa4096) ->
    public_key:generate_key({rsa, 4096, 3}).

end_per_group(_, Config) ->
    Config.

can_verify_signed(Config) ->
    Key = ?config(key, Config),
    Hash = ?config(hash, Config),
    Data = crypto:strong_rand_bytes(256),

    PubKey = ssh_signature:priv_to_public(Key),

    Signature = ssh_signature:sign(Data, Key, <<"file">>, #{hash => Hash}),
    ct:log("Signature = ~s.", [Signature]),

    ?assertMatch(
        {ok, #{public_key := PubKey}}, ssh_signature:verify(Data, Signature)
    ).

signature_can_be_verified_by_openssh(Config) ->
    ct:make_priv_dir(),
    Key = ?config(key, Config),
    Hash = ?config(hash, Config),
    PrivDir = ?config(priv_dir, Config),

    DataFile = filename:join(PrivDir, "data"),
    AllowedSignersFile = filename:join(PrivDir, "key"),
    SigFile = filename:join(PrivDir, "data.sig"),

    Data = crypto:strong_rand_bytes(256),
    ExportedKey = encode([{ssh_signature:priv_to_public(Key), []}]),

    Signature = ssh_signature:sign(Data, Key, <<"file">>, #{hash => Hash}),

    ct:log("DataB64 = ~s.", [base64:encode(Data)]),
    ct:log("ExportedKey = ~s.", [ExportedKey]),
    ct:log("Signature = ~s.", [Signature]),
    file:write_file(DataFile, Data),
    file:write_file(AllowedSignersFile, ["test@example.com ", ExportedKey]),
    file:write_file(SigFile, Signature),

    ?assert(
        ssh_keygen(
            [
                "-Y",
                "verify",
                "-n",
                "file",
                "-f",
                AllowedSignersFile,
                "-I",
                "test@example.com",
                "-s",
                SigFile
            ],
            Data
        )
    ),

    Config.

openssh_can_be_verified(Config) ->
    ct:make_priv_dir(),
    Algo = ?config(algo, Config),
    Hash = ?config(hash, Config),
    PrivDir = ?config(priv_dir, Config),

    PrivKeyFile = filename:join(PrivDir, "key"),
    PubKeyFile = filename:join(PrivDir, "key.pub"),
    DataFile = filename:join(PrivDir, "data"),
    SigFile = filename:join(PrivDir, "data.sig"),

    {Type, ExtraArgs} = openssh_keygen_args(Algo, Hash),
    true = ssh_keygen(
        ["-t", Type, "-f", PrivKeyFile, "-N", ""] ++ ExtraArgs, ""
    ),

    {ok, PubKeyPEM} = file:read_file(PubKeyFile),

    ct:log("PubKeyPEM = ~s.", [PubKeyPEM]),

    Data = crypto:strong_rand_bytes(256),
    ct:log("Data = ~s.", [base64:encode(Data)]),
    file:write_file(DataFile, Data),

    [{PK, _}] = decode(PubKeyPEM),

    true = ssh_keygen(
        ["-Y", "sign", "-f", PrivKeyFile, "-n", "test", DataFile], ""
    ),

    {ok, Signature} = file:read_file(SigFile),

    {ok, Result} = ssh_signature:verify(Data, Signature),
    ?assertMatch(#{public_key := PK}, Result),

    Config.

openssh_keygen_args(ed25519, _) -> {"ed25519", []};
openssh_keygen_args(rsa2048, H) -> {rsa(H), ["-b", "2048"]};
openssh_keygen_args(rsa3072, H) -> {rsa(H), ["-b", "3072"]};
openssh_keygen_args(rsa4096, H) -> {rsa(H), ["-b", "4096"]}.

rsa(sha256) -> "rsa-sha2-256";
rsa(sha512) -> "rsa-sha2-512".

ssh_keygen(Args, Input) ->
    Stdout = fun(_, _, Data) ->
        ct:pal("ssh-keygen -> ~s", [Data])
    end,
    exec:start(),
    Exec = os:find_executable("ssh-keygen"),
    {ok, Pid, _OsPid} = exec:run([Exec | Args], [
        stdin, monitor, {stdout, Stdout}
    ]),
    case string:is_empty(Input) of
        false ->
            exec:send(Pid, Input),
            exec:send(Pid, eof);
        true ->
            ok
    end,
    receive
        {'DOWN', _, process, _, normal} ->
            true
    after 2000 ->
        false
    end.

-if(?OTP_RELEASE < 24).
encode(Key) ->
    public_key:ssh_encode(Key, openssh_public_key).

decode(Key) ->
    public_key:ssh_decode(Key, openssh_public_key).
-else.
encode(Key) ->
    ssh_file:encode(Key, openssh_key).

decode(Key) ->
    ssh_file:decode(Key, openssh_key).
-endif.
