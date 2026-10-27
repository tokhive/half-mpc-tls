# Upstream provenance

- Repository: `https://github.com/privacy-ethereum/mpz`
- Upstream tag: `v0.1.0-alpha.6`
- Resolved commit: `6ebfe619490c3155a589fc6a3be83b0976de19dc`
- Upstream path: `crates/common`
- Imported: 2026-08-27

TokenHive bounds concurrent `Context::map` children so large offline MPC
preprocessing jobs reuse mux stream capacity instead of opening one stream for
every AES circuit batch at once.
