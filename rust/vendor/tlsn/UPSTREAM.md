# Upstream provenance

- Repository: `https://github.com/tlsnotary/tlsn`
- Package: `tlsn`
- Release: `v0.1.0-alpha.15`
- Commit: `47aee45b53e06648c1b2ad3689b367b8c923fdec`

This controlled fork contains TokenHive's verifier orchestration changes for
early upstream authentication and directional server-key release. Handshake
changes remain isolated in the sibling `tlsn-mpc-tls` fork; one-way garbled-VM
output changes are isolated in the pinned `mpz-garble*` forks.

TokenHive also permits 4096 mux streams within the existing 1 GiB aggregate
receive-window budget so asynchronously closing AES preprocessing contexts from
adjacent bounded batches do not hit the upstream default of 512.
