# TLS 1.3 KeyUpdate wire experiment

Run `python3 experiments/tls13-keyupdate/probe.py` from the repository root.
Requires Python 3, `cryptography`, and the `openssl` command. Optional
`--bytes 4096 65536 1048576 5242880` selects fixture body sizes.

This is a local compatibility experiment, **not a TLS 1.3 MPC implementation**.
It uses disposable certificates and a fake credential, verifies a complete HTTP
request spanning a client KeyUpdate against a native OpenSSL TLS server, and
checks old/new epoch authentication separation and tamper rejection. No remote
API is contacted. No credential or traffic secret is printed.

The initial handshake is ordinary TLS. Fixture traffic secrets simulate the
proposed directional release boundary. Bulk records are generated with the
next epoch's key, sequence reset to zero, and the original TLS server receives
and validates them. Reported encryption timings exclude handshake, MPC,
network transport, and model inference.

Production design and unresolved migration requirements are recorded in
[performance-design-zh.md](../../docs/performance-design-zh.md).
