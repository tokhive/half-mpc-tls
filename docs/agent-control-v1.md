# TokenHive Provider Agent Control Protocol v1

This protocol carries Provider liveness and admission state. It never carries
API keys, canonical Consumer requests, MPC shares, attachment capabilities, or
upstream plaintext.

## Transport and identity

- The Provider initiates the control connection to the Hub.
- The connection uses mutually authenticated TLS 1.3 or later.
- The Hub requires a verified Provider client certificate.
- `provider_id` is bound to the verified leaf certificate URI SAN:
  `spiffe://<trust-domain>/provider/<provider-id>`.
- The Provider verifies the Hub certificate with normal TLS hostname and chain
  validation. `InsecureSkipVerify` is rejected by the client constructor.
- TLS 1.3 here protects the Agent control plane only. The upstream selective
  MPC connection remains the separately negotiated TLS 1.2 protocol.

Messages use the existing TokenHive binary frame header and independent
monotonic sequence numbers in each direction. Agent control payloads are strict
JSON and are limited to 16 KiB at the binary codec before allocation.

## Handshake

Provider sends `FrameAgentHello`:

```json
{
  "protocol_version": 1,
  "provider_id": "provider-123",
  "instance_id": "agent-01"
}
```

Hub replies with `FrameAgentHelloAck`:

```json
{"accepted": true}
```

Rejections use only stable codes:

```json
{"accepted": false, "error_code": "unauthorized"}
```

The other v1 rejection is `duplicate`. The Hub permits only one active
connection for a Provider ID. A stale instance must disconnect or hit its
heartbeat timeout before a replacement is accepted.

## Heartbeat

The Provider sends `FrameAgentHeartbeat` immediately after the hello exchange
and then at its configured interval:

```json
{
  "counter": 1,
  "sent_at_unix_milli": 1787817600000,
  "accepting": true
}
```

`counter` starts at one and must increase by exactly one. It is checked in
addition to the binary frame sequence. The Hub uses its local receipt time for
liveness; Provider wall-clock time is diagnostic only.

Hub replies with `FrameAgentHeartbeatAck`:

```json
{
  "counter": 1,
  "received_at_unix_milli": 1787817600001
}
```

`accepting=true` makes the Provider's bound precompute keys online.
`accepting=false`, connection loss, heartbeat timeout, replay, malformed JSON,
or a sequence mismatch drains those keys to zero. Idle sessions close
immediately; active leases finish and are destroyed when returned.

## Reconnection

The Provider client retries transport failures and `duplicate` responses with
bounded exponential backoff. Authentication and protocol errors are terminal
until configuration or certificates change. A connection which remained live
for at least two heartbeat intervals resets the backoff.

The Hub assigns a generation to every accepted connection. Disconnect cleanup
only affects the matching generation, so delayed cleanup from an old instance
cannot mark a newer connection offline.

## Reverse data connection slots

The data listener uses the existing mandatory mTLS 1.3 and SPIFFE Provider
identity checks. After authentication and before tunnel frames, the Agent sends
six bytes: ASCII `THD1`, followed by a big-endian unsigned 16-bit slot in 0..255.
The handshake and hello have a combined 10-second deadline. Invalid hellos and
unlisted Providers are rejected. Hub and Agent must be upgraded together.

`data_tunnels` defaults to 32 independent connections per Provider. The registry
reserves one connection generation exclusively for a whole warmed session,
including its RPC, MPC and bridge-control streams. Exhaustion returns unavailable
without sharing a reserved connection. Closing a session closes the physical
connection first; the Agent reconnects that slot. Replacing a slot invalidates its
old session, and old cleanup cannot remove the replacement. Slots never replace
certificate identity checks. Control heartbeats retain their existing protocol.
