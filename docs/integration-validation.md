# Go integration acceptance — 2026-10-24

Implemented public entry points:

- `client.New`, `Chat`, `Stream` / `Recv`, `Models`, `Task`, `TaskByKey`.
- `hub.Run`, `RunFile`, `LoadConfig`, exported configuration and capacity profiles.
- `make build`, `make smoke`, `make smoke-tls13`, `make smoke-tls13-large`, `make demo`; compilable Go client and embedded examples.

Passed checks on the final integration implementation:

- `go test -race ./...` and `go vet ./...`.
- `cargo test --workspace` (expensive ignored tests remain opt-in), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`.
- `go test -count=1 -tags=integration ./internal/sidecar` using a real Rust process.
- Independent external Go module importing both public packages through a local module replacement, without importing internal packages.
- `make smoke`, followed by the expanded `python3 scripts/demo.py --check`: two Rust sidecars, Go Hub, Go Provider Agent, authenticated mTLS reverse connections, private-CA TLS 1.2 upstream, real two-party selective MPC, HTTP and Go SDK JSON/SSE requests. Four upstream requests yielded four durable receipts. The duplicate key did not redispatch upstream. Task lookup returned settled state and the fixture's 28-micro charge, and foreign-account lookups returned 404. SIGTERM exited all four processes and removed both sidecar sockets.

Additional regression coverage includes malformed/duplicate JSON, empty-array preservation, automatic stream usage, account-scoped idempotency, task state after ledger recovery, foreign-task isolation, closed-ledger rejection, client cancellation, truncated SSE without `[DONE]`, redirect rejection, typed API errors and reserved request-field protection.

The generated local fixture validates the deployed wiring, not paid upstream service compatibility or public-network throughput. The original TLS 1.2 acceptance used the 4 KiB baseline profile. Existing cryptographic tests and performance results are documented in `benchmark-results.md` and `performance-design-zh.md`.

## TLS 1.3 integration acceptance

The real MPC engine is now connected to both sidecar roles and Go routes. Both sidecars explicitly select `--tls-version 1.3`; the route selects `tls_version: "1.3"`. The default remains TLS 1.2. Version mismatches, inconsistent engine advertisements, missing KeyUpdate/output-authentication capabilities and mismatched capacities fail before session creation. Pool inventory is keyed by TLS version as well as the existing identity and capacity fields.

Executed against local OpenSSL HTTPS upstreams with generated certificates and credentials:

| Command | Result |
| --- | --- |
| `python3 scripts/demo.py --check --tls-version 1.3` | PASS: TLS 1.3 baseline, JSON/SSE, Go SDK, auth, idempotency, durable settlement, clean teardown |
| `python3 scripts/demo.py --check --tls-version 1.3 --capacity 5m --prompt-bytes 5241856` | PASS: near-5-MiB prompts for both JSON and SSE, plus short Go SDK calls in the same 5-MiB pool |
| `python3 scripts/demo.py --check` | PASS: TLS 1.2 default regression with the same business checks |

Each deployment received exactly four upstream requests and wrote four receipts; the duplicate idempotency key did not redispatch. Both sidecar sockets were removed and all four processes exited successfully. TLS 1.3 used the existing Provider-local delivery ACK and response/settlement path throughout, without a plain TLS fallback.

Logs for this workspace run: `/tmp/tls13-smoke.log`, `/tmp/tls13-smoke-5m.log`, `/tmp/tls12-regression-smoke.log`. Temporary deployment artifacts: `/tmp/tokenhive-demo-9d8wolng`, `/tmp/tokenhive-demo-190jzjam`, `/tmp/tokenhive-demo-8769yron` respectively. These are local artifacts, not repository fixtures.

The independent Rust engine's explicit ignored tests also passed the full 4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB and 5 MiB matrix with rustls, server KeyUpdate, wrong DNS, mismatched request plans and invalid credentials. See [engine validation and trust boundary](../rust/crates/tls13/README.md). The four-process acceptance above covers the smallest and largest profiles; intermediate deployment profiles, real paid upstream compatibility and public-network tail latency are not claimed by these runs.


Final integration checks passed again after wiring TLS 1.3: `go test -race ./...`, `go vet ./...`, `cargo test --locked --workspace`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, and `cargo fmt --all --check`. `go test -count=1 -tags=integration ./internal/sidecar` exercised real Rust processes for both the omitted TLS flag (1.2 default) and explicit 1.3. New tests cover the shared TLS 1.3 capability fixture, required authenticated-output/KeyUpdate/delivery-ACK features, both directions of route-versus-engine mismatch before commands or upstream dial, and separate pool leases across versions.
