SSH signatures for Erlang
=====

Implementation of [SSH signatures][ssh-keygen-sign] in Erlang. It uses only
stuff distributed with OTP, so no external dependencies needed.

[ssh-keygen-sign]: https://man.openbsd.org/ssh-keygen#Y~4

Currently supported algorithms:

- RSA
- Ed25519
- Ed448 - not tested, as my implementation of OpenSSH do not support Ed448 keys

## Usage

There are just 3 exported functions:

- `sign/{3,4}` which allows signing data
- `verify/2` that verifies the signature for given data and outputs details
  about signature

```erlang
% First we need the private key that we will use for signing.
% For the purpose of this example just use RSA-4096
SecretKey = public_key:generate_key({rsa, 4096, 3}),

Data = <<"Foo">>,

% Sign data using our key. 3rd argument there is a namespace, that must be
% non-empty string.
Signature = ssh_signature:sign(Data, SecretKey, "text"),

% The created signature is already in armoured (ASCII-only) format.

% Now we can check if the signature is correct
{ok, #{public_key := PubKey, ns := <<"test">>, signature := Sig}} =
    ssh_signature:verify(Data, Signature).
% Notice that we do not pass public key to verify/2, it is left to the user to
% check whether the returned public key is trusted.
```

## License

See [LICENSE](LICENSE)
