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

TBD

## License

See [LICENSE](LICENSE)
