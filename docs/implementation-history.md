# Implementation history and repository milestone snapshot

> Historical snapshot captured 2026-10-27. Use [current architecture](current-architecture.md) and the [repository README](../README.md) for current deployment defaults and supported behavior.

This repository contains the design and runnable MVP implementation of TokenHive's
TLS 1.2 / TLS 1.3 Selective MPC relay. TLS 1.2 remains the default; TLS 1.3
is selected explicitly on both sidecars and the Go route, without fallback.

## Security model

The current design trusts Hub to follow the protocol and perform request
validation, response authentication, and settlement correctly. Provider may be
malicious; the upstream API and its certificate trust chain are trusted.
Consumers trust Hub rather than independently verifying TLS evidence. Provider
credentials remain local to Provider and enter MPC as private inputs; their
privacy assumes a protocol-following Hub. Protecting credentials against an
actively malicious or compromised Hub is outside the current scope. This trust
assumption does not relax nonce uniqueness, one-shot consumption, authenticated
MPC outputs, request binding, or fail-closed handling of invalid Provider evidence.

## Go business integration

Public packages [`client`](../client/) and [`hub`](../hub/) support a reusable Go SDK
and embedding the Hub in an existing Go process. The SDK includes JSON/SSE,
context cancellation, connection reuse, typed errors, and account-scoped task
lookup by task ID or idempotency key. Session acquisition uses a bounded FIFO
queue per pool; `hub.Config.MaxWaiters` and `QueueWaitTimeoutMS` control its
limits, with typed HTTP 503 overload errors. See the
[Chinese integration guide](business-integration-zh.md) and
[compilable examples](../examples/go/).

```sh
make smoke  # real four-process MPC + HTTP + Go SDK + durable settlement
make smoke-tls13 # same acceptance with the real TLS 1.3 MPC engine
make demo   # keep a local deployment running for application integration
```

The local demo uses generated credentials and a deterministic private TLS
upstream, and never calls a paid model API. Production credentials and PKI
remain deployment configuration. The default example now matches the tested
4 KiB sidecar baseline; larger profiles require explicit matching configuration.

## End-to-end load testing

`make bench-e2e` runs the public Go SDK against the real four-process TLS 1.3
service, with a local HTTPS fixture that simulates inference delay and timed
streaming. It covers ready inventory, sustained concurrency, fixed arrival rates,
large prompts and a delayed Provider data link. Generated credentials stay in a
private temporary directory; the test makes no paid API calls. Use
`make bench-e2e-quick` to check the harness. The full run takes roughly 12 minutes
on the two-CPU development host and writes per-request timings, errors, receipts
and sampled CPU/RSS to the printed artifact directory. See the
[baseline and queue-spin fix](performance/e2e-2026-10-24.md) and the
[FIFO queue results and overload verification](performance/e2e-2026-10-26.md).

## Local stability and recovery validation

`make validate-local` runs fault recovery during active SSE, a private Go Hub CPU
profile, and three consecutive five-minute load phases. It uses generated local
credentials and a synthetic TLS upstream. The test restarts its own processes,
cleans their stale sockets, and checks interrupted task refunds, receipt replay,
response deadlines and downstream disconnect settlement. Artifacts include
per-minute timings and sampled RSS, thread and file descriptor counts.

See the [local validation report](performance/production-validation-2026-10-26.md).
This is a bounded local test; production supervisors, real upstreams, cross-machine
networks and day-long soak tests still require separate validation.

## Performance work

The TLS 1.2 path now evaluates nonce-bound client AES and tag masks during
warming, keeps credential keystream secret in MPC, and enforces one-shot
record consumption. It pipelines sidecar/MPC writes in a bounded ACK window,
bridges upstream sockets locally at the Provider, selects routes using ready
inventory and observed response-header latency, and budgets additional pool
space for active streaming leases. Each session reserves its own physical
Provider data connection for its entire lifetime; a global warm limit bounds
preprocessing across providers and capacities. Hub and Provider Agent must be
upgraded together for the versioned data-connection hello. Both sidecars also
require the new `precomputed-client-aes` capability; upgrade all four components
together. Six exact request capacity profiles can be
mapped to separate sidecar processes on each role. Measurements, configuration,
and TLS 1.3 KeyUpdate integration are described in
[`performance-design-zh.md`](performance-design-zh.md).
The TLS 1.3 engine uses real two-party ECDHE/HKDF, authenticated MPC outputs,
and a fixed credential-prefix circuit. After delivery of the prefix and
KeyUpdate, Hub encrypts the public body locally with the next traffic key.
It supports P-256 / TLS_AES_128_GCM_SHA256 / HTTP/1.1 only. See the
[engine profile and trust boundary](../rust/crates/tls13/README.md); this assumes
a protocol-following Hub and does not claim an independent cryptographic audit.

## Implementation status

### M0: complete

Implemented:

- versioned Hub/Provider binary control frames with monotonic message numbers;
- a checked per-session lifecycle and retry-safety state;
- exact host/port Provider egress policy;
- multiplexed reverse TCP connections initiated from the Provider network;
- a development-only Hub-terminated TLS 1.2 engine;
- local end-to-end tests, including TLS 1.2 over the Provider tunnel.

The development TLS engine does **not** protect Provider credentials from Hub.
It is only a replaceable implementation of the engine boundary used to test M0.
M1-M3 replace it with the Rust TLS 1.2 Selective MPC sidecars described in
[`tls12-selective-mpc-implementation-zh.md`](tls12-selective-mpc-implementation-zh.md).

### M1: complete

Implemented:

- Rust 1.98 workspace with TLSNotary pinned to commit
  `47aee45b53e06648c1b2ad3689b367b8c923fdec` (`v0.1.0-alpha.15`);
- MPZ dependencies locked to commit
  `6ebfe619490c3155a589fc6a3be83b0976de19dc`;
- controlled `tlsn`, `tlsn-mpc-tls`, `tlsn-deap`, `mpz-garble`, and
  `mpz-garble-core` forks, each with pinned upstream provenance in its vendor
  directory;
- Hub-side verification of both Finished messages at the application-traffic
  boundary, without waiting for the TLS connection to close;
- Hub-side certificate chain, target DNS name, and ECDHE signature validation;
- Hub-only API for decoding TLS 1.2 `server_write_key` and fixed IV, gated by
  a non-forgeable `VerifiedHandshake` proof and consumable only once;
- a matched one-way garbled-VM output: Provider sends decoding labels but has
  no local cleartext future, while only Hub can receive the server key/IV;
- redacted, non-serializable server key material which is zeroized on drop;
- shared Go/Rust sidecar capability negotiation with no TLS 1.3 downgrade;
- an exact cross-language MPC capacity commitment: protocol v1 supports a
  4 KiB/four-record baseline, intermediate 16 KiB, 64 KiB, 256 KiB and 1 MiB
  profiles, and an opt-in 5 MiB/323-record request profile, all with a 16 MiB
  response and six online response records; mismatched profiles fail negotiation;
- matching Go/Rust bounded binary frame codecs, role-bound hello exchange, and
  role-specific command validation documented in
  [`sidecar-rpc-v1.md`](sidecar-rpc-v1.md);
- runnable role-fixed Rust sidecar processes over mode-0600 Unix sockets in a
  private runtime directory, with strict lifecycle parameters,
  connection-owned sessions, bounded streaming, cancellation, and explicit
  rejection of Provider `api_key` fields;
- capability-gated full-duplex MPC attachments on both roles, a Provider-only
  upstream attachment, and a required Hub-only authenticated response
  attachment, with 64 KiB framing and half-close semantics;
- cumulative Provider upstream-delivery acknowledgements bound to byte count
  and SHA-256 prefix: handshake transport flushes and selective request
  completion wait until the Provider Go relay's complete upstream write
  returns, with mismatch or ambiguity failing the session;
- a request-independent warm-session pool keyed by Provider, local credential
  reference, authenticated upstream identity, TLS version, and exact MPC capacity; it
  maintains a target ready inventory with bounded concurrency, warm timeouts,
  exponential retry backoff, health/idle/lifetime eviction, exclusive leases,
  and deterministic shutdown of idle and leased one-time material;
- a concrete paired-sidecar warmer which creates both role-owned sessions,
  attaches and relays the MPC channels, opens the upstream connection through
  the Provider tunnel, runs MPC preprocessing and the authenticated TLS 1.2
  handshake, and retains one authenticated HTTP response stream;
- a Provider-initiated Agent control plane over mandatory mutual TLS 1.3, with
  SPIFFE URI SAN binding of Provider IDs, bounded strict heartbeat frames,
  replay counters, duplicate-instance generations, heartbeat timeout draining,
  explicit admission state, and bounded reconnect backoff; the protocol is
  documented in [`agent-control-v1.md`](agent-control-v1.md);
- real role-specific `run_handshake` dispatch: Provider retains the live TLS
  connection while Hub independently authenticates the certificate, DNS name,
  ECDHE signature and Finished messages before retaining server traffic keys;
- a context-aware Go Unix sidecar client and a build-tagged cross-language
  process integration test;
- cross-language JSON and binary fixtures for the local sidecar contract;
- a real two-party MPC TLS 1.2 integration test which authenticates the local
  fixture and releases server keys while the TLS connection is still open;
- a real negative integration test which rejects a valid certificate presented
  for the wrong verifier-selected DNS identity without authorizing key release.

Malicious-path coverage includes wrong certificate identity, bounded/corrupt
peer identity, exact Finished comparison, one-shot directional key release,
tampered delivery acknowledgement, forbidden server-record injection, and
fail-closed connection/session teardown.

### M2: complete

Implemented:

- a fixed `openai_chat_completions_v1` HTTP/1.1 adapter which discards the
  possibility of caller-supplied headers, canonicalizes a JSON object, and
  emits one zero-filled Provider credential slot;
- a generated, versioned secret layout and SHA-256 binding over the complete
  public request template;
- independently parsed request-model binding on both sidecars; model is
  required inside the canonical JSON covered by the request hash;
- independently parsed streaming binding on both sidecars; `stream=true`
  requires hashed `stream_options.include_usage=true`, and successful RPC
  results return the derived `streaming` mode;
- matching Go/Rust fixtures and Rust-side validation of adapter, authenticated
  host, header order, content length, credential slot, task ID, and request
  hash before MPC dispatch;
- strict selective RPC metadata which never accepts caller-supplied secret
  offsets;
- mixed-input AES-GCM request encryption where Hub owns every canonical public
  byte and Provider owns only the generated credential span;
- one-shot selective plans checked independently by both MPC parties across
  TLS record fragmentation, with non-selective application writes rejected;
- a canonical public-record fast path: only records overlapping the Provider
  credential use mixed-input encryption, while following body-only records
  decode AES keystream evaluated during warming and XOR locally after both parties verify
  the exact public template;
- Provider-local credential resolution through an injectable resolver, with
  the complete credential-bearing request zeroized after it is queued;
- real sidecar dispatch from `encrypt_request` / `contribute_request_encryption`
  into the retained TLS 1.2 connection, covered by an ignored full two-party
  MPC integration test.

The standalone Provider sidecar loads a strict, mode-0600 local credential
file through an atomically reloadable resolver; `SIGHUP` validates and swaps a
complete new snapshot without interrupting active sessions, while a failed
reload retains the previous snapshot. Old credential values are zeroized when
their last in-flight copy is dropped. The resolver interface also permits a
later system-keyring adapter. The reproducible release benchmark matrix and
current same-host measurements are in
[`benchmark-results.md`](benchmark-results.md). The 5 MiB tier is implemented
as an explicit capability but still requires full-size resource and
deployed-network benchmarks before production admission. Ambiguous JSON, modified canonical bytes,
caller-supplied secret metadata, request binding mismatch, and duplicate task
dispatch all have negative fixtures.

### Warm-session pool

`internal/precompute` moves the existing per-session MPC preprocessing and
upstream TLS handshake ahead of Consumer request arrival. A pool key includes
the Provider ID, Provider-local credential reference, upstream host/port/SNI,
and the exact negotiated MPC capacity, so incompatible sessions cannot be
mixed. `ConservativeConfig` defaults to one request per session: after a lease
is released, the live TLS connection and its one-time MPC state are destroyed
and replenished asynchronously.

Inventory can be changed per key at runtime with `RegisterWithLimits` and
`SetTarget`. Scaling a key to zero closes idle sessions immediately but lets an
active lease finish before destroying it. `Stats` exposes ready/leased/warming
counts, hit and miss totals, cumulative wait and warm durations, consecutive
and cumulative warm failures, and health/idle/lifetime/scale-down evictions.
These values are intentionally dependency-free so a deployment can export
them through its existing metrics system without placing Provider credential
references in library-owned labels.

`Autoscaler` can manage those targets automatically. It estimates each key's
inventory as `request rate * successful warm duration * safety factor`, clamps
the result to configured minimum and maximum bounds, scales up immediately on
pool misses, and requires consecutive quiet samples before gradual scale-down.
Provider offline events drain the target to zero without terminating active
leases. Its snapshot also reports required versus configured warm concurrency
and a saturation flag, because a larger idle inventory cannot compensate for a
long-term request rate above preprocessing throughput.

`internal/agent` connects Provider liveness to the autoscaler. An authenticated
heartbeat with `accepting=true` enables the Provider's keys; an explicit drain,
connection loss, timeout, replay, or malformed control message drives them to
zero without interrupting active leases. Agent identity comes from a verified
SPIFFE URI SAN rather than a self-asserted JSON field. The control channel uses
mutual TLS 1.3 and is separate from the upstream MPC TLS connection.

`SidecarWarmer` is the concrete implementation for local or split-machine
sidecars. In split mode, `providerconn.Registry` uses the Provider-initiated
mTLS data tunnel for sidecar streams and a session-owned local-bridge control
handle. The Provider Agent opens and bridges the allowlisted upstream socket
locally, preserving write-delivery acknowledgements without a Hub hairpin.
Precomputed secrets are kept only in live process memory
and are never serialized, cloned, or persisted.

The sidecars advertise exactly one selected profile per process: the 4 KiB
baseline by default, or `--capacity 16k|64k|256k|1m|5m` on both roles.
`hub_sidecar_sockets` and `sidecar_sockets` map profile names to distinct local
process sockets; the existing single-socket settings remain supported.
The concrete warmer verifies that both negotiated profiles
exactly match the route key. The large profile reserves 323 client-direction
records and uses bounded 128-way preprocessing batches so it does not exhaust
the MPC multiplexer's stream limit. Its total AES preprocessing work remains
linear in the configured capacity and should be admitted only after measuring
memory, warm latency, and concurrent-session throughput on deployment hardware.

### M3: complete for the repository MVP

Implemented server-record capture from the live TLS 1.2 engine, blind response
handling on Provider, Hub-local sequence/nonce/AES-GCM authentication and
decryption, and a required Hub response attachment with bounded fail-closed buffering.
The real two-party selective MPC test now verifies an authenticated HTTP
response delivered through that channel. Response records incur no MPC AES or
GHASH work and are bounded to 16 MiB per session.

The Go response layer now keeps one parser across the persistent attachment,
uses the standard library HTTP/1.1 chunked/trailer decoder, streams bounded SSE
events across arbitrary TLS-record boundaries, and records a SHA-256 outcome
only after the decoded body reaches a clean EOF. It extracts OpenAI model, ID,
and normalized usage fields while rejecting duplicate JSON keys, ambiguous
token field names, negative/fractional counts, and inconsistent totals. The
session state machine cannot return to `READY` until response completion is
explicitly recorded.

The Consumer relay now buffers successful JSON responses until authenticated
EOF, validates model and usage before writing any response bytes, and validates
SSE one event at a time. It withholds the SSE `[DONE]` marker until authenticated
EOF, stable model/ID, final usage, and durable receipt commit. Authenticated
non-2xx responses are relayed as non-billable outcomes. The required receipt
contains task/Provider IDs, request and response hashes, requested and actual
models, upstream request/response IDs, status, body size, and normalized usage.
If a Consumer disconnects during SSE, the relay stops downstream writes but
continues authenticating and draining the upstream response through final usage
and EOF, then commits the billable receipt. Disconnecting therefore cannot be
used to receive a partial answer while avoiding settlement.

Receipts are persisted through a mode-0600, single-writer JSONL outbox keyed by
`task_id`. Identical retries are idempotent, conflicting evidence is rejected,
records form a SHA-256 hash chain, each append is synced before terminal success
is exposed to the Consumer, and a torn final record is removed during recovery.
The outbox deliberately does not define pricing or mutate balances; an account
ledger must consume it idempotently with the same `task_id` key.

`internal/settlement.Ledger` now defines that accounting state machine with
integer currency micros and versioned price snapshots. It reserves the maximum
input/output cost before dispatch, rejects insufficient funds, settles actual
authenticated usage, refunds unused reserve or the full amount for non-billable
responses, and atomically splits Provider credit from platform fees. Funding,
reservation, settlement, cancellation, and outbox replay are idempotent; usage
above the reserved maxima is held as `review_required`, retaining the receipt
and reserve without charging or paying out. These tasks remain visible through
account-scoped task lookup and do not block replay of other receipts. Binding
conflicts and storage failures still fail closed. `Processor` persists evidence before ledger application and can replay
the outbox after a crash. `DurableLedger` stores every accepted account
transition in a synced, hash-chained, single-writer log and reconstructs the
complete balance/reservation state after restart.

`internal/api` exposes chat completions, model discovery, health/readiness and
Consumer-scoped task status endpoints. It stores digests of
TokenHive Consumer keys, enforces per-Consumer rate and concurrency limits,
applies the MPC body limit and request timeout, and emits stable OpenAI-shaped
errors. `internal/coordinator` deterministically selects a healthy route,
reserves maximum cost, acquires a warmed session, checks the two-party request
binding, validates the response, and settles the receipt. Client idempotency keys are scoped by Consumer account. A task ID is never
dispatched twice. Streaming HTTP requests automatically include usage before
canonical request binding; duplicate JSON keys remain rejected. Protocol failures feed a persisted weighted Provider
quarantine tracker which fails closed on storage errors.

`cmd/tokenhive-hub` and `cmd/tokenhive-provider-agent` are the runnable
split-machine assembly. Both Agent channels are Provider initiated and use
mutual TLS 1.3 with SPIFFE Provider identities. The upstream model connection
inside the selective MPC engine defaults to TLS 1.2; TLS 1.3 is explicitly
selected with matching sidecar flags and route configuration. Strict example configuration
is in [`config`](../config/); Hub configuration contains Consumer credentials and
must be mode 0600.

Remaining work is deployment-specific: issue real certificates, provision
Provider credentials and Consumer balances, approve price/model policy, and
run the MPC capacity matrix on the intended network before admitting traffic.

Run the current test suite:

```sh
go test ./...
go test -race ./...
go test ./internal/canonical -run '^$' -bench BenchmarkBuildOpenAIChatCompletions -benchmem
go test ./internal/gateway -run '^$' -bench BenchmarkRelayOpenAISSE -benchmem
go build ./cmd/tokenhive-hub ./cmd/tokenhive-provider-agent

cd rust
cargo test --workspace
cargo test -p tlsn --test tokenhive_mpc -- --ignored
cargo test -p tokenhive-sidecar attached_channels_run_real_selective_mpc_tls_request -- --ignored
TOKENHIVE_MPC_TEST_PUBLIC_BODY=1 cargo test --release -p tokenhive-sidecar \
  attached_channels_run_real_selective_mpc_tls_request -- --ignored --nocapture
cargo clippy --workspace --all-targets -- -D warnings

# Builds and starts a real Rust sidecar from the Go integration test.
cd ..
go test -count=1 -tags=integration ./internal/sidecar

# Release-mode real MPC capacity matrix (three samples per size by default).
./scripts/benchmark-mpc-capacity.sh
```
