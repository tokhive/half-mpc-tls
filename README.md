# TokenHive Half-MPC TLS

TokenHive relays LLM requests through Provider-owned upstream connections. Go
handles admission, routing, streaming and accounting; role-fixed Rust sidecars
perform selective MPC TLS. Hub authenticates and decrypts responses locally.

The current model trusts Hub to follow the protocol and settle correctly.
Provider may be malicious. Provider credentials stay local and enter MPC as
private inputs; credential privacy assumes a protocol-following Hub. Consumers
trust Hub rather than independently verifying TLS evidence. The upstream API
and its certificate trust chain are trusted. Nonce uniqueness, one-shot
consumption, authenticated MPC outputs, request binding and fail-closed handling
of invalid Provider evidence remain mandatory.

See [current architecture](docs/current-architecture.md) and
[architecture decisions](docs/adr/README.md).

## Go integration

Public packages [client](client/) and [hub](hub/) support a Go SDK and embedding
Hub in an existing process. They provide JSON/SSE, cancellation, connection
reuse, typed errors and account-scoped task lookup. Session acquisition uses a
bounded FIFO per pool, with explicit overload errors.

Read the [integration guide](docs/business-integration-zh.md) and
[compilable examples](examples/go/). A Consumer disconnect during a response
still permits authentication and settlement through the original deadline.
Successful JSON and SSE DONE wait for durable settlement. Authenticated usage
above the reserved maxima enters `review_required`, retaining evidence and the
reserve for reconciliation while other tasks recover normally.

## Run locally

```sh
make smoke              # TLS 1.2, real four-process MPC, JSON/SSE/SDK/settlement
make smoke-tls13        # TLS 1.3, one shared 5 MiB capacity profile
make smoke-tls13-large  # full-size TLS 1.3 request
make demo               # keep the local TLS 1.2 deployment running
python3 scripts/demo.py --tls-version 1.3
```

Local runs generate temporary credentials and a private TLS upstream. They do
not call a paid model API. Deployment certificates, Provider credentials,
Consumer balances, pricing and model policy must be configured separately.

## Engine and capacity selection

TLS 1.2 remains the compatibility default: sidecars and routes use the exact
4 KiB baseline unless configured otherwise. Six explicit profiles are available
for TLS 1.2, where preprocessing cost grows with the selected request budget.

TLS 1.3 is selected explicitly on both sidecars and routes, with no fallback.
A TLS 1.3 sidecar without `--capacity` now advertises the shared `5m` profile;
use [the TLS 1.3 configuration](config/hub-tls13.example.json) for the matching
route. One process and pool per role accepts every request size up to that
limit; the credential circuit remains bounded to 1 KiB. Explicit older capacity
flags remain supported for compatibility. Defaults do not auto-negotiate a
capacity or TLS version that the peer did not advertise.

TLS 1.3 supports P-256, TLS_AES_128_GCM_SHA256 and HTTP/1.1. Each current engine
uses one session per request. [Engine scope and trust model](rust/crates/tls13/README.md)
and [deployment compatibility](docs/adr/0004-upstream-compatibility-validation.md)
explain the limits. Public network probing does not replace real Provider
exit-network and authenticated business acceptance.

## Validation and profiling

```sh
go test -race ./...
go vet ./...
go build ./cmd/tokenhive-hub ./cmd/tokenhive-provider-agent
# Verify the same release sidecar artifact used by the deployment.
TMPDIR=/tmp TOKENHIVE_TEST_SIDECAR_BINARY="$PWD/rust/target/release/tokenhive-sidecar" \
  go test -tags=integration ./internal/sidecar
cargo test --manifest-path rust/Cargo.toml --locked --workspace
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- -D warnings

# Real two-party tests are explicitly ignored by the ordinary workspace run.
cargo test --manifest-path rust/Cargo.toml --locked --release -p tokenhive-tls13 \
  --test real -- --ignored --nocapture --test-threads=1

make bench-e2e-quick
make validate-local
python3 scripts/profile-warm.py --tls-version 1.3 --seconds 30
```

Stage profiling is opt-in with `TOKENHIVE_PROFILE_STAGES=1`. It records fixed
phase names, wall time and whole-process CPU deltas, without credentials or
traffic secrets. Nested/overlapping intervals cannot be added. Native stack
sampling is retained separately and unavailable sampling is reported explicitly.
See [profiling](docs/warm-profiling.md).

TLS 1.3 reuses secret keyed HMAC prefix states within each VM to reduce repeated
HKDF circuit evaluation. This changes the MPC schedule: both sidecars must
support `tls13-keyed-hmac-state` and schedule revision 2. Drain affected Providers
and upgrade the matching roles together; incompatible peers reject before
credential contribution. The outer RPC remains v1. See [ADR 0007](docs/adr/0007-session-local-hmac-prefix-states.md).

## Documentation

- [Current architecture and lifecycle](docs/current-architecture.md)
- [Business integration](docs/business-integration-zh.md)
- [Sidecar RPC](docs/sidecar-rpc-v1.md) and [Agent control](docs/agent-control-v1.md)
- [Performance design and measurements](docs/performance-design-zh.md)
- [Latest optimization evidence](docs/performance/optimization-2026-10-27.md) and
  [continuous-load / recovery results](docs/performance/production-validation-2026-10-27.md)
- [Design review and remaining validation](docs/design-review-2026-10-27.md)
- [Implementation milestone history](docs/implementation-history.md)

The original [Chinese](docs/half-mpc-tls-binding-zh.md) and
[English](docs/half-mpc-tls-binding-en.md) protocol papers are historical design
proposals. Their connection-reuse assumptions and estimated timings are not the
current implementation contract or production SLO.
