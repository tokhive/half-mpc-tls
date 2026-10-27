# TokenHive Sidecar RPC v1

This protocol connects each Go service to its local Rust MPC-TLS sidecar. It
is not the remote Hub/Provider transport and must only be exposed over a Unix
socket or an equivalently protected loopback channel.

## Binary frame

All integers use network byte order.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `THV1` (`0x54485631`) |
| 4 | 1 | protocol version `1` |
| 5 | 1 | frame type |
| 6 | 2 | flags |
| 8 | 8 | session ID |
| 16 | 8 | direction-local sequence |
| 24 | 4 | payload length |

Sequences start at one and increase by exactly one independently in each
direction. Any invalid header, sequence gap, oversized payload, partial write,
or truncated read poisons the connection; it must be closed and no session on
it may be reused.

Control payloads are at most 1 MiB. `Data` and `SidecarStream` payloads are at
most 64 KiB, with the limit checked before allocation. One complete sidecar
stream is at most 16 MiB. Hello and command/result JSON have tighter semantic
limits of 16 KiB and 64 KiB respectively.

## Frame types

| Value | Name | Session ID | Payload |
|---:|---|---:|---|
| 9 | `SidecarHello` | 0 | strict JSON `RpcHello` |
| 10 | `SidecarHelloAck` | 0 | strict JSON `RpcHelloAck` |
| 11 | `SidecarCommand` | non-zero | strict JSON `RpcCommand` |
| 12 | `SidecarResult` | non-zero | strict JSON `RpcResult` |
| 13 | `SidecarStream` | non-zero | raw bounded bytes |
| 14 | `SidecarStreamEnd` | non-zero | empty |
| 15 | `SidecarCancel` | non-zero | empty or a stable reason code |
| 16 | `DeliveryAck` | non-zero | cumulative byte count and SHA-256 prefix |

Flags are zero in v1. Frame values 1 through 8 remain allocated to the remote
TCP tunnel protocol.

## Connection handshake

The Go client sends exactly one `SidecarHello` containing protocol version 1
and the expected sidecar role. The Rust server returns `SidecarHelloAck` only
when the expected role equals its configured role and its capabilities pass
the selected engine validation. `--tls-version 1.2` (default) advertises
`tls12-selective-mpc`; explicit `--tls-version 1.3` advertises
`tls13-selective-mpc`, exclusively version `1.3` and
`TLS_AES_128_GCM_SHA256`. See `testdata/sidecar-capabilities-tls13.json`.

Unknown JSON fields, mixed or inconsistent version advertisements, missing
required features, and an unsupported cipher suite are fatal protocol errors.
Both engines and the Go route `tls_version` must match. Empty route version
means `1.2`. Pool keys include the version; no automatic downgrade is attempted.

For TLS 1.2, `precomputed-client-aes` is a required capability. It commits both roles to
nonce-bound client AES evaluation during warming, before READY. Record zero is
the 16-byte Finished; the one application request uses 16 KiB fragments and one
exact tail, followed by at most one two-byte alert. A shorter request burns its
unused record suffixes. No second request or material reuse is allowed. A
credential record decodes only ciphertext; public records decode their own
keystream only after canonical-template authorization. An old peer without this
capability is rejected before session setup. Upgrade both sidecars and both Go
components together; the frame format remains version 1.

TLS 1.3 instead requires `tls13-keyupdate` and `authenticated-mpc-output`, plus
server-key-release, selective-request-encryption, bidirectional-attachments,
authenticated-response-channel and provider-delivery-ack. Hub is the garbler;
Provider is the evaluator. Hub-only secrets use independently masked outputs
and normal MAC-authenticated decoding. TLS 1.3 does not use the TLS 1.2 DEAP
output path or its public-body keystream schedule.

Capabilities also contain an exact `mpc_capacity` object. Protocol v1 supports
six exact profiles. The default baseline is:

```json
{
  "max_request_bytes": 4096,
  "max_request_records": 4,
  "max_response_bytes": 16777216,
  "max_response_records_online": 6
}
```

The largest opt-in public-body profile is:

```json
{
  "max_request_bytes": 5242880,
  "max_request_records": 323,
  "max_response_bytes": 16777216,
  "max_response_records_online": 6
}
```

Both parties must advertise the same supported profile. The Go canonicalizer
and both Rust request validators reject a request over `max_request_bytes`
before installing a selective plan or consuming MPC capacity.
Intermediate profiles are `16k` (16384 bytes / 4 records), `64k` (65536 / 7),
`256k` (262144 / 19), and `1m` (1048576 / 67). All share the response limits
above. The cross-language fixture is `testdata/mpc-capacities.json`.
Each sidecar process advertises one profile selected with `--capacity` on both
roles. Deployment socket maps allow multiple profiles without mixing sessions. The route's capacity must exactly match the sidecar
pair, and the warm-session pool never mixes profiles.

## Commands

Every command is bound to a non-zero `session_id` in the frame and a non-zero
`request_id` in the JSON body. Request IDs cannot be reused on a connection.
v1 permits at most one in-flight operation per session, so stream frames are
correlated by session. Bulk canonical requests and TLS records use stream
frames instead of JSON.

`encrypt_request`, `feed_server_records`, and
`contribute_request_encryption` are followed immediately by zero or more
`SidecarStream` frames and one `SidecarStreamEnd`. Every frame must carry the
command's session ID. Empty chunks, interleaved sessions, non-zero flags, and
streams over 16 MiB are fatal protocol errors. A client may send
`SidecarCancel` instead of the remaining stream; a non-empty cancellation
reason is at most 256 bytes and matches `[a-z0-9_]+`.

Long-lived interactive channels do not use the bounded command-input stream.
They use a separate RPC connection which sends one attachment command and,
after an `ok` result, switches permanently to full-duplex `SidecarStream`
frames. `SidecarStreamEnd` half-closes only its sending direction. Attachment
channels have no aggregate byte limit because MPC preprocessing can exceed the
command-input limit; the 64 KiB per-frame bound and monotonic sequences still
apply.

The Provider upstream attachment additionally accepts `DeliveryAck` from Go
to Rust. Its payload is exactly 40 bytes: an 8-byte big-endian, non-zero
cumulative byte count followed by the SHA-256 digest of exactly that byte
prefix. Go sends one ACK only after a complete `net.Conn.Write` loop has
returned for the corresponding sidecar frame. ACKs must match the next pending
prefix exactly; unsolicited, duplicate, skipped, out-of-order, or mismatched
ACKs fail the attachment and the TLS session. MPC and response attachments
reject this frame type.

Hub sidecars accept:

- `create_session`
- `run_handshake`
- `encrypt_request`
- `feed_server_records`
- `close_session`
- `attach_mpc_channel`
- `attach_response_channel`

Provider sidecars accept:

- `bind_credential`
- `run_handshake`
- `contribute_request_encryption`
- `destroy_session`
- `attach_mpc_channel`
- `attach_upstream_channel`

The Provider API accepts a local `credential_id`; it does not accept an API
key value. Credentials, TLS keys, MPC shares, canonical request bodies, and
decrypted upstream responses must never be included in command/result errors
or logged RPC metadata.

Lifecycle parameter objects are strict JSON:

```json
{
  "upstream_policy": {
    "host": "api.example.com",
    "port": 443,
    "server_name": "api.example.com"
  }
}
```

`bind_credential` additionally requires a top-level `credential_id`. Unknown
fields, including `api_key`, are rejected. `create_session` and
`bind_credential` return a random 32-byte `attachment_token` encoded as 64
lowercase hexadecimal characters. It authorizes separate local connections to
attach channels to that session and must not be logged. It is zeroized in the
Rust session registry when the session is destroyed.

`attach_mpc_channel` is available on both roles. `attach_upstream_channel` is
Provider-only and carries a TCP connection which the Provider Go agent already
opened through its egress policy. Go must bridge it with
`sidecar.BridgeProviderUpstream`, which preserves frame boundaries and emits
the required delivery ACKs. A generic `io.Copy` bridge is insufficient.
`attach_response_channel` is Hub-only and
must be treated by its client as read-only: it emits only authenticated TLS
application plaintext. Each channel kind can be attached once. An invalid
token and an unknown session both return `attachment_rejected` so the API does
not become a session enumeration oracle.

`run_handshake` consumes the required attachments exactly once. Provider
requires both `mpc` and `upstream`, retains the live TLS connection, and returns
`handshake_running`. Hub requires both `mpc` and `response`, and returns `ready`
only after upstream certificate/DNS/ECDHE/Finished authentication and one-way
server-key release.
The coordinator treats the pair as ready only after receiving Hub's successful
result. Handshake execution is bounded by a sidecar timeout and cannot be
retried on the consumed session.

`encrypt_request` and `contribute_request_encryption` use the same strict
metadata object:

```json
{
  "task_id": "task_01HZZZZZZZZZZZZZZZZZZZZZZZ",
  "adapter": "openai_chat_completions_v1",
  "credential_length": 48,
  "public_request_hash": "64-lowercase-hex-sha256"
}
```

`task_id` is 1-128 ASCII alphanumeric, hyphen, or underscore characters and
`credential_length` is 1-512 bytes. Hub sends the canonical request template
as the `encrypt_request` input stream. Provider sends the same zero-filled
template as the `contribute_request_encryption` input stream. Both sidecars
therefore validate the same authenticated host, exact bytes, and hash before
installing an MPC plan. Credential bytes are resolved inside the Provider
sidecar from its already-bound local reference and never enter either RPC
stream.

The canonical JSON object must contain a 1-256 byte model identifier made of
ASCII alphanumeric characters plus `-._:/`. Both successful selective request
results include `requested_model` and `streaming`; both are parsed independently
by each sidecar from the exact body covered by `public_request_hash`, never
accepted as separate RPC metadata. If `stream` is absent or false,
`stream_options` must be absent. If `stream=true`, the body must also contain
`stream_options.include_usage=true`; otherwise both sidecars reject the
canonical request before installing an MPC plan.

The first adapter has exactly this HTTP/1.1 shape and header order:

```text
POST /v1/chat/completions HTTP/1.1\r\n
Host: <authenticated server_name>\r\n
Authorization: Bearer <credential_length zero bytes>\r\n
Content-Type: application/json\r\n
Content-Length: <canonical JSON byte length>\r\n
Connection: keep-alive\r\n
\r\n
<canonical JSON object>
```

The zero bytes are an internal MPC placeholder, not bytes sent upstream. The
sidecars derive the single `bearer_credential` span from this template; no RPC
accepts caller-supplied offsets or a caller-supplied secret layout. Hub rejects
non-zero placeholder bytes, a non-object JSON body, a non-canonical decimal
content length, an unexpected host/header/path, and a SHA-256 mismatch before
dispatching to the MPC engine.

For TLS 1.2, record fragmentation is part of the independently checked one-shot plan.
A record overlapping `bearer_credential` uses mixed-input selective
encryption. Any subsequent record with no secret overlap uses public mode:
both parties first require the bytes to equal their canonical template, decode
the preprocessed AES keystream, and XOR the public plaintext locally. Provider
cannot replace body bytes without the Hub side rejecting the plan. Public mode
removes the mixed-input plaintext circuit, but AES keystream preprocessing and
GCM authentication still scale linearly with request length.

For TLS 1.3, both roles validate the same canonical request and hash. MPC
produces the credential prefix through its CRLF and KeyUpdate under the old
application key. Upstream flush waits for the existing delivery ACK before
Hub receives the next client traffic secret through authenticated MPC output.
Hub then encrypts the remaining headers/body locally in 16 KiB records and
batches at most 512 KiB per relay ACK. The old credential key is never released.
The TLS 1.3 profile and protocol-following Hub assumption are documented in
`rust/crates/tls13/README.md`.

On success, Hub returns `request_prepared` after installing its one-shot
template plan. Provider returns `request_delivered` after resolving the local
credential, installing the matching one-shot secret ranges, encrypting the
request, and waiting until every resulting TLS byte has a matching Provider
upstream delivery ACK. The ACK means the Provider relay's socket write
completed; it does not prove that the upstream application processed the
request and is not billable evidence. Billing still requires an authenticated,
validated response and a durable receipt. The successful result includes
`upstream_delivery.cumulative_bytes`, `upstream_delivery.request_bytes`, and
the lowercase hexadecimal cumulative ciphertext `sha256`; this metadata is
operational retry/audit evidence and contains no plaintext or credential.

After the handshake, Provider forwards server TLS records without learning
application plaintext. On TLS 1.2, Hub checks each record sequence, version,
explicit nonce, and AES-128-GCM tag with the released server-direction key,
then writes authenticated HTTP/1.1 bytes to `attach_response_channel` in record
order. Authentication failure, replay, malformed records, non-close alerts, or
channel failure closes the response stream without emitting the failed record.
TLS 1.3 instead authenticates implicit sequence numbers, key epochs and inner
content types, processes server KeyUpdate and sends a reply when requested.
Its relay reads one bounded record at a time. On TLS 1.2, the encrypted-record
queue is bounded to 16 records; if a slow consumer fills
it, the session fails closed instead of buffering without limit. The session
response byte limit is 16 MiB. `feed_server_records` remains a reserved
v1 command and returns `not_implemented`; records are captured directly from
the live MPC-TLS engine.

Hub Go code wraps the response attachment in `internal/response.Stream`. One
parser remains attached for the entire keep-alive connection so buffered bytes
cannot be lost between responses. It requires HTTP/1.1, rejects upgrades and
unexpected content encodings, limits headers to 64 KiB and decoded bodies to
16 MiB, and uses `net/http` for chunked decoding and trailers. A response body
must reach clean EOF before the next response can be parsed or the session can
return to `READY`; truncation, overflow, or early close makes the response path
terminal. SSE events are incrementally decoded with a 1 MiB per-event limit.
For OpenAI responses, the parser holds response ID and model stable across SSE
events, requires `[DONE]`, normalizes the Chat Completions and Responses API
usage field names, and rejects ambiguous, negative, fractional, or
arithmetically inconsistent token counts. A billable result must match an
explicit adapter-supplied response-model allowlist.

`internal/gateway.RelayOpenAI` additionally requires a durable receipt sink.
For JSON and authenticated non-2xx responses, it commits the receipt before
writing status/body to the Consumer. For SSE it may flush validated data events
incrementally, but commits the receipt before releasing `[DONE]`. A receipt
commit failure therefore cannot expose terminal success. The included
`internal/settlement.Journal` provides a synced, hash-chained, single-writer
outbox with `task_id` idempotency; it is not itself the balance ledger.
After a downstream SSE write failure, the Hub stops writing to that Consumer
but continues validating and draining the authenticated upstream stream. A
valid final usage event, `[DONE]`, and EOF still produce a receipt, preventing
intentional Consumer disconnects from bypassing settlement.
The reference `settlement.Ledger` freezes integer-micro input/output prices and
Provider payout rates at reservation time, then consumes the authenticated
usage exactly once. `settlement.Processor` always appends the receipt before
ledger application and replays all journal records idempotently after a crash.
Production deployments may use Journal directly as the Gateway sink and run
Processor asynchronously, or use Processor synchronously before terminal
success; the account-ledger implementation must provide real database
transactions and unique task/funding keys.

A successful `RpcResult` may contain a `data` object and never contains error
fields. An error result contains a stable `error_code`, optional redacted
`error_message`, and no `data`.

## Unix service

The Rust process is started independently for each role:

```sh
tokenhive-sidecar --role hub --socket /run/tokenhive/hub-sidecar.sock
tokenhive-sidecar --role provider --socket /run/tokenhive/provider-sidecar.sock \
  --credential-file /run/tokenhive/provider-credentials.json
```

The optional Provider credential file has strict shape
`{"version":1,"credentials":{"credential-id":"api-key"}}`. It must be a
non-symlink regular file with no group or other permission bits (normally mode
`0600`), is bounded to 1 MiB and 1024 entries, and rejects duplicate IDs,
unknown fields, unsafe HTTP-header bytes, empty values, and values over 512
bytes. The encoded file buffer and parsed credential values are zeroized. Hub
mode rejects `--credential-file`; deployments using a system keyring can inject
another `CredentialResolver` instead.

In Provider mode, sending `SIGHUP` causes the sidecar to load and fully validate
a replacement credential file before taking a short write lock and swapping
the snapshot. Existing sessions resolve their credential at selective-request
dispatch, so they use either the complete old or complete new generation. A
failed reload is logged without credential values and leaves the old snapshot
active. Operators should write a new mode-0600 file and atomically rename it
over the configured path before sending `SIGHUP`; in-place partial writes are
not supported. Hub mode accepts `SIGHUP` as a no-op.

The socket parent directory must be a real (non-symlink) directory private to
the service account, with no group/other permission bits (normally mode
`0700`). This closes the permission window between binding and setting the
socket itself to mode `0600`. The process refuses to replace an existing
filesystem entry. A session belongs to the local connection that created or
bound it; another connection cannot take it over, and disconnecting destroys
all of that connection's sessions.

## Remote transport and local upstream bridge

Sidecar RPC and MPC transported through the Provider reverse tunnel use bounded
pipelined writes (8 frames / 512 KiB outstanding), with exact cumulative ACK
validation. Frame headers and payloads are written together. RPC responses remain
operation barriers; complete request delivery still requires the Provider
sidecar's matching upstream write acknowledgement.

In split deployment, the Provider Agent now attaches its local sidecar directly
to an allowlisted upstream socket. A bounded, versioned bridge-control stream
owns these local resources and closes with the session. No TLS wire bytes
travel through that control stream. See [the performance design](performance-design-zh.md)
for the control format, socket maps, lifecycle, and rollout requirements.
