-module(ssh_signature_SUITE).

-include_lib("public_key/include/public_key.hrl").

-compile(export_all).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

all() ->
    [{group, basic}].

groups() ->
    Tests = [can_verify_signed, can_signature_can_be_verified_by_ssh_keygen],
    Hashes = [sha256, sha512],
    Algos = [
        ed25519,
        % ed448, % OpenSSH 8 seens to not support it
        rsa2048,
        rsa3072,
        rsa4096
    ],
    AlgoTests = [{Algo, [parallel], Tests} || Algo <- Algos],
    HashTests = [{Hash, [parallel], AlgoTests} || Hash <- Hashes],
    [{basic, [parallel, shuffle], HashTests}].

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
    Key = create_key(GroupName),
    ct:log("~p", [Key]),
    [{key, Key} | Config].

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

    Signature = ssh_signature:sign(Data, Key, <<"file">>, #{hash => Hash}),
    ct:log("~s", [Signature]),

    ?assertMatch({ok, _}, ssh_signature:verify(Data, Signature)).

can_signature_can_be_verified_by_ssh_keygen(Config) ->
    ct:make_priv_dir(),
    Key = ?config(key, Config),
    Hash = ?config(hash, Config),
    PrivDir = ?config(priv_dir, Config),

    AllowedSignersFile = filename:join(PrivDir, "key"),
    SigFile = filename:join(PrivDir, "data.sig"),

    Data = crypto:strong_rand_bytes(256),
    ExportedKey = ssh_file:encode([{priv_to_public(Key), []}], openssh_key),

    Signature = ssh_signature:sign(Data, Key, <<"file">>, #{hash => Hash}),

    ct:log("~s", [ExportedKey]),
    ct:log("~s", [Signature]),
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

ssh_keygen(Args, Input) ->
    Stdout = fun(_, _, Data) ->
        ct:pal("ssh-keygen -> ~s", [Data])
    end,
    exec:start(),
    Exec = os:find_executable("ssh-keygen"),
    {ok, Pid, _OsPid} = exec:run([Exec | Args], [
        stdin, monitor, {stdout, Stdout}
    ]),
    exec:send(Pid, Input),
    exec:send(Pid, eof),
    receive
        {'DOWN', _, process, _, normal} ->
            true
    after 1000 ->
        fuck
    end.

priv_to_public({ed_pri, Type, Pub, _Priv}) ->
    {ed_pub, Type, Pub};
priv_to_public(#'ECPrivateKey'{parameters = {namedCurve, Curve}, publicKey = PK}) ->
    Type =
        case Curve of
            ?'id-Ed25519' ->
                ed25519;
            ?'id-Ed448' ->
                ed448
        end,
    {ed_pub, Type, PK};
priv_to_public(#'RSAPrivateKey'{modulus = Mod, publicExponent = Exp}) ->
    #'RSAPublicKey'{modulus = Mod, publicExponent = Exp};
priv_to_public(Other) ->
    Other.
