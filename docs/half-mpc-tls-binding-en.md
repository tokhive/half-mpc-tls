# Half-MPC TLS Binding: Verifiable LLM API Relay Without Trusted Hardware

> A protocol for proving that an LLM API relay (Provider) actually forwarded requests to the claimed upstream API (e.g., OpenAI) and returned genuine responses — without requiring TEE hardware, and without exposing the Provider's API key.

> Current security model (confirmed 2026-10-27): Hub is trusted to follow the protocol and perform verification and settlement correctly. Provider may be malicious; the upstream API and its certificate trust chain are trusted. Credential privacy assumes a protocol-following Hub and does not cover an actively malicious or compromised Hub. Consumers trust Hub rather than independently verifying TLS evidence. Some performance and connection-reuse descriptions below reflect the original design; see [README](../README.md) for current implementation status.

## Table of Contents

- [1. Overview](#1-overview)
- [2. Problem Statement](#2-problem-statement)
- [3. Threat Model](#3-threat-model)
- [4. Background: TLS 1.3](#4-background-tls-13)
  - [4.1 Why TLS Exists](#41-why-tls-exists)
  - [4.2 Symmetric vs Asymmetric Cryptography](#42-symmetric-vs-asymmetric-cryptography)
  - [4.3 The TLS Handshake: Bridging Asymmetric and Symmetric](#43-the-tls-handshake-bridging-asymmetric-and-symmetric)
  - [4.4 TLS 1.3 Full Handshake Walkthrough](#44-tls-13-full-handshake-walkthrough)
  - [4.5 Key Derivation: From Shared Secret to Traffic Keys](#45-key-derivation-from-shared-secret-to-traffic-keys)
  - [4.6 AES-GCM Record Encryption](#46-aes-gcm-record-encryption)
  - [4.7 HTTP Keep-Alive: One Handshake, Many Requests](#47-http-keep-alive-one-handshake-many-requests)
  - [4.8 TLS Key Update](#48-tls-key-update)
  - [4.9 Why TLS Cannot Prove Origin to a Third Party](#49-why-tls-cannot-prove-origin-to-a-third-party)
- [5. Background: Multi-Party Computation (MPC)](#5-background-multi-party-computation-mpc)
  - [5.1 What MPC Does](#51-what-mpc-does)
  - [5.2 Garbled Circuits](#52-garbled-circuits)
  - [5.3 Oblivious Transfer (OT)](#53-oblivious-transfer-ot)
  - [5.4 Offline/Online Separation](#54-offlineonline-separation)
- [6. Protocol Design](#6-protocol-design)
  - [6.1 Roles](#61-roles)
  - [6.2 Phase 0: MPC-TLS Handshake (One-Time)](#62-phase-0-mpc-tls-handshake-one-time)
  - [6.3 Phase 1: Asymmetric Key Distribution](#63-phase-1-asymmetric-key-distribution)
  - [6.4 Phase 2: Request Encryption (Per Request)](#64-phase-2-request-encryption-per-request)
  - [6.5 Phase 3: Response Decryption (Per Request)](#65-phase-3-response-decryption-per-request)
  - [6.6 Phase 4: Verification & Settlement](#66-phase-4-verification--settlement)
- [7. Why "Half-MPC"](#7-why-half-mpc)
- [8. Security Analysis](#8-security-analysis)
- [9. Performance Analysis](#9-performance-analysis)
- [10. Connection Pool & Lifecycle](#10-connection-pool--lifecycle)
- [11. Comparison With Alternative Approaches](#11-comparison-with-alternative-approaches)
- [12. Implementation Notes](#12-implementation-notes)
- [13. Limitations & Future Work](#13-limitations--future-work)

---

## 1. Overview

This document describes a **Half-MPC TLS Binding** protocol designed for LLM API quota-sharing platforms. In such platforms, a **Provider** shares their LLM API access (e.g., an OpenAI API key or a Codex OAuth token) with **Consumers** through a central **Hub**. The core challenge is verifying that the Provider actually relayed requests to the claimed upstream API and returned genuine responses, rather than substituting a cheaper model or tampering with the output.

The "Half-MPC" name reflects the key architectural insight: **MPC (Multi-Party Computation) is used only for request encryption (client→server direction), while response decryption (server→client direction) is performed by the Hub alone.** This asymmetric design provides strong verification guarantees with minimal performance overhead.

### Key Properties

| Property | Guarantee |
|---|---|
| **Response authenticity** | Hub can independently verify that responses came from the upstream API (e.g., api.openai.com) |
| **API key privacy** | The protocol does not reveal the Provider's plaintext API key to a protocol-following Hub |
| **IP preservation** | The upstream API sees the Provider's IP address, not the Hub's |
| **No special hardware** | No TEE (Intel TDX, AWS Nitro, etc.) required on either side |
| **Low latency overhead** | ~2ms per request for MPC encryption; 0ms for response decryption |

---

## 2. Problem Statement

Consider the following architecture for LLM API quota sharing:

```
Consumer ──request──> Hub ──task──> Provider ──API call──> api.openai.com
Consumer <──response── Hub <──result── Provider <──response── api.openai.com
```

The Provider holds an API key (or OAuth token) for the upstream API. The Hub dispatches Consumer requests to available Providers. The trust problem is:

> **How does the Hub verify that the Provider actually called `api.openai.com` with the Consumer's prompt and returned the genuine response, rather than substituting a cheaper model, modifying the prompt, or tampering with the output?**

### Existing Approaches and Their Limitations

| Approach | How it works | Limitation |
|---|---|---|
| **Self-signed receipts** (e.g., AntSeed ResponseAuth) | Provider signs a hash of the response it served | Provider can tamper first, then sign the tampered version |
| **TEE attestation** (e.g., Intel TDX) | Run the relay inside a hardware enclave that can be remotely attested | Requires specialized server hardware (4th+ Gen Xeon); high cost and operational complexity |
| **Full MPC-TLS** (e.g., TLSNotary) | Hub and Provider jointly operate the TLS connection via Multi-Party Computation | Both request and response go through MPC — high latency (~seconds per request), especially for LLM streaming |
| **Proxy mode** (Hub as TCP/TLS proxy) | Hub establishes the TLS connection and forwards traffic through Provider's TCP socket | Upstream API sees Hub's IP when Hub proxies; or multiple Provider keys from one Hub IP triggers account bans |

Half-MPC TLS Binding addresses all four limitations simultaneously.

---

## 3. Threat Model

### Trusted Parties

- **Hub**: Operated by the platform and trusted to follow the protocol, verify requests and responses, and perform settlement correctly. It may be curious about Provider's API key but does not actively modify MPC inputs, circuits, records, or key-release steps to obtain credentials. An actively malicious or compromised Hub is outside the current threat model.
- **Upstream API** (e.g., OpenAI): Trusted to return honest responses for valid requests.

### Untrusted Parties

- **Provider**: May attempt to:
  - Substitute a cheaper model (e.g., serve a quantized open-source model instead of GPT-4o)
  - Modify the Consumer's prompt before forwarding
  - Tamper with the upstream API's response
  - Claim to have called OpenAI but actually call a different (cheaper) service

### Assets to Protect

| Asset | Protection goal |
|---|---|
| Provider's API key | Do not reveal its plaintext to a protocol-following Hub |
| Consumer's prompt | Provider sees it (inherent to inference relay; prompt privacy requires additional TEE on Hub side) |
| Response integrity | Hub must verify responses are genuine and unmodified |
| Provider's IP identity | Upstream API must see Provider's IP, not Hub's, to avoid account bans |

---

## 4. Background: TLS 1.3

This section provides a detailed primer on TLS 1.3 — the encryption protocol that secures HTTPS connections. Understanding TLS internals is essential because the Half-MPC protocol works by splitting TLS operations between two parties.

### 4.1 Why TLS Exists

When your browser (or an API client) connects to `api.openai.com`, the data travels through many intermediate routers, ISPs, and network devices. Without encryption, any of these intermediaries could:

- **Read** the data (eavesdropping): see your API key, your prompt, the model's response
- **Modify** the data (tampering): change your prompt, alter the response, inject content
- **Impersonate** the server (spoofing): pretend to be `api.openai.com` and return fake responses

TLS (Transport Layer Security) prevents all three by establishing an encrypted, authenticated channel between the client and server. TLS 1.3 (RFC 8446, published 2018) is the current version, significantly simpler and faster than TLS 1.2.

### 4.2 Symmetric vs Asymmetric Cryptography

TLS uses two types of cryptography, each with distinct strengths:

**Symmetric cryptography** (e.g., AES-GCM):
- One shared secret key encrypts and decrypts
- Extremely fast (~10 GB/s on modern CPUs with AES-NI)
- Problem: how do two parties who have never met agree on a shared key?

```
Alice ──AES(key, "hello")──> ciphertext ──AES(key, ciphertext)──> Bob sees "hello"
                                          (same key on both sides)
```

**Asymmetric cryptography** (e.g., ECDH, RSA):
- Two mathematically related keys: public key (shared freely) and private key (kept secret)
- Anyone can encrypt with the public key; only the private key holder can decrypt
- Much slower than symmetric (~1000x)
- Used for two purposes:
  - **Key exchange**: agree on a shared secret over an insecure channel (ECDH)
  - **Digital signatures**: prove identity (RSA/ECDSA signatures on certificates)

```
Server publishes: public_key
Alice computes:   shared_secret = ECDH(alice_private, server_public)
Server computes:  shared_secret = ECDH(server_private, alice_public)
                  (both get the same secret, but an eavesdropper cannot)
```

**TLS combines both**: use asymmetric crypto once (slow, but works without pre-shared secrets) to establish a symmetric key, then use symmetric crypto (fast) for all actual data.

### 4.3 The TLS Handshake: Bridging Asymmetric and Symmetric

The TLS handshake is the initial phase of a TLS connection. Its job is to:

1. **Authenticate the server**: verify that you're talking to the real `api.openai.com` (via certificate chain)
2. **Negotiate a cipher suite**: agree on which algorithms to use (e.g., `TLS_AES_128_GCM_SHA256`)
3. **Establish shared secrets**: use ECDH key exchange to derive symmetric session keys
4. **Derive traffic keys**: run the shared secret through a key derivation function to produce the actual encryption keys

After the handshake, both sides have identical symmetric keys and all subsequent data is encrypted with AES-GCM (or ChaCha20-Poly1305).

### 4.4 TLS 1.3 Full Handshake Walkthrough

TLS 1.3 completes in a single round-trip (1-RTT):

```
Client (e.g., Provider)                         Server (e.g., api.openai.com)
          |                                               |
  Step 1  |── ClientHello ───────────────────────────────>|
          |   • supported cipher suites                   |
          |   • supported groups (curves)                 |
          |   • key_share: g^a (ECDH public key)          |
          |   • random (32 bytes)                         |
          |                                               |
  Step 2  |<─ ServerHello ────────────────────────────────|
          |   • chosen cipher suite                       |
          |   • key_share: g^b (ECDH public key)          |
          |   • random (32 bytes)                         |
          |                                               |
          |   ─── Everything below is encrypted ───       |
          |        (using handshake traffic keys)          |
          |                                               |
  Step 3  |<─ {EncryptedExtensions} ──────────────────────|
          |   • server parameters                         |
          |                                               |
  Step 4  |<─ {Certificate} ──────────────────────────────|
          |   • server's X.509 certificate chain          |
          |   • (proves this is api.openai.com)           |
          |                                               |
  Step 5  |<─ {CertificateVerify} ────────────────────────|
          |   • signature over handshake transcript       |
          |   • (proves server holds the private key      |
          |      matching the certificate)                |
          |                                               |
  Step 6  |<─ {Finished} ────────────────────────────────|
          |   • MAC over entire handshake transcript      |
          |   • (confirms handshake integrity)            |
          |                                               |
  Step 7  |── {Finished} ───────────────────────────────>|
          |   • client's MAC over handshake transcript    |
          |                                               |
          ════════ Handshake complete ════════════════════
          |                                               |
  Step 8  |── {Application Data} ───────────────────────>|
          |   • e.g., HTTP POST /v1/chat/completions      |
          |<─ {Application Data} ─────────────────────────|
          |   • e.g., HTTP 200 OK + SSE stream            |
```

**What happens at each step:**

- **Step 1 (ClientHello)**: The client proposes cryptographic parameters and sends its ECDH public key `g^a` (where `a` is a random private value the client generated).

- **Step 2 (ServerHello)**: The server picks a cipher suite and sends its ECDH public key `g^b`. At this point, both sides can compute the ECDH shared secret: `shared_secret = g^(a·b)`. The client computes it as `(g^b)^a`, the server as `(g^a)^b` — both yield the same value, but an eavesdropper who sees only `g^a` and `g^b` cannot compute `g^(a·b)` (this is the Elliptic Curve Diffie-Hellman assumption).

- **Steps 3-6**: The server sends its certificate chain, a signature proving it holds the certificate's private key, and a MAC confirming the handshake wasn't tampered with. These messages are already encrypted using keys derived from the ECDH shared secret.

- **Step 7**: The client sends its own Finished message, confirming the handshake from its side.

- **Step 8+**: Application data (HTTP requests and responses) flows, encrypted with the application traffic keys derived from the shared secret.

### 4.5 Key Derivation: From Shared Secret to Traffic Keys

The ECDH shared secret is not used directly as an encryption key. Instead, it feeds into the **HKDF (HMAC-based Key Derivation Function)** key schedule, which derives multiple independent keys:

```
                    ECDH shared secret: g^(a·b)
                              |
                    ┌─────────┴──────────┐
                    │   HKDF-Extract     │
                    │   (salt=0, ikm=0)  │
                    └─────────┬──────────┘
                              |
                        Early Secret
                              |
                    ┌─────────┴──────────┐
                    │   HKDF-Extract     │
                    │  (ES, shared_sec)  │
                    └─────────┬──────────┘
                              |
                      Handshake Secret
                              |
              ┌───────────────┼───────────────┐
              |                               |
    HKDF-Expand-Label             HKDF-Expand-Label
    "c hs traffic"                "s hs traffic"
              |                               |
  client_handshake_               server_handshake_
  traffic_secret                  traffic_secret
  (encrypts client                (encrypts server
   handshake msgs)                 handshake msgs)
                              |
                    ┌─────────┴──────────┐
                    │   HKDF-Extract     │
                    │   (HS, 0)          │
                    └─────────┬──────────┘
                              |
                        Master Secret
                              |
              ┌───────────────┼───────────────┐
              |                               |
    HKDF-Expand-Label             HKDF-Expand-Label
    "c ap traffic"                "s ap traffic"
              |                               |
  client_application_             server_application_
  traffic_secret                  traffic_secret
              |                               |
     ┌────────┴────────┐            ┌────────┴────────┐
     |                 |            |                 |
  client_           client_      server_           server_
  write_key         write_iv     write_key         write_iv
  (AES key)         (GCM IV)     (AES key)         (GCM IV)
```

**Critical property for Half-MPC**: The client and server application traffic secrets are derived through **independent HKDF-Expand-Label calls** from the same Master Secret. They are cryptographically independent: knowing one does not reveal the other. This allows us to reveal the server traffic secret to the Hub while keeping the client traffic secret shared.

Each traffic secret is further expanded into:
- A **write key** (16 or 32 bytes): the AES key for encryption/decryption
- A **write IV** (12 bytes): the initialization vector for AES-GCM nonce construction

### 4.6 AES-GCM Record Encryption

Every piece of application data in TLS 1.3 is encrypted as a **TLS record** using AES-GCM (Authenticated Encryption with Associated Data). AES-GCM combines two operations:

#### AES-CTR (Counter Mode) — Confidentiality

AES-CTR generates a **keystream** by encrypting successive counter values, then XORs the keystream with the plaintext:

```
For a plaintext of N blocks (each block = 16 bytes):

  counter_block[0] = nonce ∥ 0x00000002     (counter starts at 2 for data)
  counter_block[1] = nonce ∥ 0x00000003
  ...
  counter_block[i] = nonce ∥ (i + 2)

  keystream[i]  = AES(key, counter_block[i])     ← AES block cipher
  ciphertext[i] = plaintext[i] ⊕ keystream[i]    ← simple XOR
```

Where:
- `key` = the write key (derived from the traffic secret)
- `nonce` = `write_iv ⊕ sequence_number` (12 bytes; sequence_number increments per record, starting from 0)

**Important**: each 16-byte block is encrypted independently. The encryption of block `i` depends only on `key`, `nonce`, and `i` — not on any other block's plaintext. This property enables the segmented MPC approach where some blocks can be processed differently.

#### GHASH — Authentication

GHASH computes a polynomial hash over the ciphertext and AAD (Additional Authenticated Data) in the finite field GF(2^128):

```
H = AES(key, 0^128)                              ← hash subkey

GHASH(H, A, C):
  result = 0
  for each 128-bit block a_i in A (AAD):
    result = (result ⊕ a_i) · H                  ← multiply in GF(2^128)
  for each 128-bit block c_i in C (ciphertext):
    result = (result ⊕ c_i) · H
  result = (result ⊕ len(A)∥len(C)) · H
  return result
```

The final **authentication tag** is:

```
tag = GHASH(H, AAD, ciphertext) ⊕ AES(key, nonce ∥ 0x00000001)
```

The tag is appended to the ciphertext (16 bytes). The receiver recomputes the tag and verifies it matches. If any bit of the ciphertext or AAD was modified, the tag will not match (with overwhelming probability), and the record is rejected.

#### Complete TLS Record Structure

```
┌──────────────┬─────────────────────────────────────────────┬─────────┐
│ Record Header│               Encrypted Payload             │   Tag   │
│   (5 bytes)  │                                             │(16 bytes│
│              │  ciphertext[0] | ciphertext[1] | ... | 0x17 │         │
│  type=0x17   │                                             │         │
│  ver=0x0303  │  (plaintext = HTTP data + content_type byte)│         │
│  length      │                                             │         │
└──────────────┴─────────────────────────────────────────────┴─────────┘
                               |
                         AAD for GHASH
                     (= Record Header bytes)
```

The `0x17` byte at the end of the plaintext is the **real content type** (application data = 23 = 0x17). The outer record header always says `0x17` and `0x0303` regardless of the actual content, for backward compatibility.

### 4.7 HTTP Keep-Alive: One Handshake, Many Requests

HTTP/1.1 defaults to persistent connections (`Connection: keep-alive`). This means a single TCP + TLS connection can carry multiple HTTP request/response cycles:

```
┌──────────────── One TLS session (one handshake) ────────────────┐
│                                                                  │
│  Request 1:   POST /v1/chat/completions    →  200 OK (SSE)      │
│  (TLS records #0-#3)                          (TLS records #4-#50)│
│                                                                  │
│  Request 2:   POST /v1/chat/completions    →  200 OK (SSE)      │
│  (TLS records #51-#54)                        (TLS records #55-#120)│
│                                                                  │
│  ...                                                             │
│                                                                  │
│  Request N:   POST /v1/chat/completions    →  200 OK (SSE)      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

The TLS **sequence number** (used to construct the nonce) increments monotonically across all records in the session. It starts at 0 and never resets (until a Key Update, which resets it to 0 with a new key).

This is significant for the Half-MPC protocol: **the expensive MPC-TLS handshake is done once, and all subsequent requests on the connection use the same shared key material.**

### 4.8 TLS Key Update

Either party can trigger a **Key Update** during a session (TLS 1.3, §4.6.3). This derives a new traffic secret from the current one:

```
new_traffic_secret = HKDF-Expand-Label(
    current_traffic_secret,
    "traffic upd",
    "",
    Hash.length                    // 32 bytes for SHA-256
)
```

After a Key Update:
- New write keys and IVs are derived from the new traffic secret
- The sequence number resets to 0
- Old keys are discarded

Key Update does NOT require a new handshake. It is a lightweight operation (one HMAC call).

In the Half-MPC context:
- **Client traffic secret Key Update**: Hub and Provider must jointly compute the new secret from their existing shares (a lightweight 2PC-HMAC, ~1ms)
- **Server traffic secret Key Update**: Hub holds the complete secret and derives the new one locally (zero MPC cost)

### 4.9 Why TLS Cannot Prove Origin to a Third Party

This is the fundamental problem that the Half-MPC protocol solves. Consider:

1. The Provider (TLS client) connects to `api.openai.com` (TLS server)
2. TLS uses **symmetric-key** authentication (AES-GCM MACs)
3. The client and server share the **same key**
4. Therefore, the client can compute valid authentication tags for **any** data — not just data the server actually sent

If the Provider gives you a TLS record with a valid tag, you cannot tell whether:
- (a) The server actually sent that data (genuine), or
- (b) The Provider fabricated the data and computed the tag itself (forged)

Both would produce identical, valid ciphertext + tag pairs.

**This is fundamentally different from asymmetric signatures** (like HTTPS certificates). A certificate is signed with the CA's private key, which only the CA holds — so a valid certificate signature proves the CA issued it. But TLS record authentication uses symmetric keys that both client and server hold — so a valid MAC proves nothing about who created it.

This is why simply forwarding TLS records to a third party is not sufficient proof. Some form of intervention during the TLS session is needed to prevent the client from unilaterally forging data. The Half-MPC protocol achieves this by splitting the TLS key so that neither party holds the complete key alone.

---

## 5. Background: Multi-Party Computation (MPC)

### 5.1 What MPC Does

Multi-Party Computation allows two or more parties to jointly compute a function over their private inputs, without revealing those inputs to each other.

In mathematical terms: parties P₁ and P₂ hold private inputs x₁ and x₂. They want to compute f(x₁, x₂) such that:
- Both parties learn the output f(x₁, x₂)
- P₁ learns nothing about x₂ (beyond what f(x₁, x₂) reveals)
- P₂ learns nothing about x₁ (beyond what f(x₁, x₂) reveals)

For the Half-MPC protocol, the function is `AES(key, input)` where:
- Hub holds `key_H` (its share of the AES key)
- Provider holds `key_P` (its share of the AES key)
- The complete key is `key = key_H ⊕ key_P`
- Neither party should learn the other's share or the complete key

### 5.2 Garbled Circuits

Garbled Circuits (Yao's protocol) is the most practical 2PC technique for evaluating boolean circuits like AES.

**How it works (simplified):**

1. **Circuit representation**: Express the function (e.g., AES) as a boolean circuit — a network of AND and XOR gates with wire connections.

2. **Garbling** (done by the "garbler", e.g., Hub):
   - For each wire in the circuit, generate two random **labels**: one representing 0, one representing 1
   - For each gate, encrypt the output labels under the appropriate input labels
   - The garbled gate table allows someone with the correct input labels to decrypt exactly one output label — but reveals nothing about the underlying bit values

3. **Evaluation** (done by the "evaluator", e.g., Provider):
   - The evaluator receives the garbled circuit and the labels corresponding to their actual input bits
   - The evaluator processes each gate: using the two input labels, they can decrypt exactly one entry in the garbled table, obtaining the output label
   - At the end, the evaluator has output labels that encode the result

4. **Output decoding**: The garbler reveals which output labels correspond to 0 and 1, allowing the evaluator to decode the result

**AES-128 as a boolean circuit**:
- Input: 128-bit key + 128-bit block = 256 input bits
- Output: 128-bit encrypted block
- Circuit size: approximately **6,400 AND gates** and ~25,000 XOR gates
- XOR gates are "free" under the Free-XOR optimization (zero communication cost)
- Total garbled table size: ~6,400 × 16 bytes ≈ **100 KB per AES evaluation**

### 5.3 Oblivious Transfer (OT)

The evaluator needs to receive labels corresponding to their actual input bits — but without revealing those bits to the garbler. This is achieved through **Oblivious Transfer**:

- The garbler holds two labels for each of the evaluator's input wires: (label₀, label₁)
- The evaluator holds a choice bit b ∈ {0, 1}
- After OT, the evaluator learns label_b, and the garbler learns nothing about b

For AES with a 128-bit private input from the evaluator, this requires 128 OTs. With **OT Extension**, the cost of many OTs is reduced to a small number of base OTs plus cheap symmetric-key operations.

### 5.4 Offline/Online Separation

Garbled circuit protocols naturally split into two phases:

**Offline phase** (can be done before the actual input is known):
- Garbler generates the garbled circuit and garbled tables
- Base OTs for OT Extension are established
- This can happen during idle time (e.g., while waiting for LLM responses)

**Online phase** (when the actual computation is needed):
- Transfer input labels via OT (using pre-established OT Extension)
- Evaluator processes the garbled circuit
- Decode outputs

The online phase is extremely fast — typically **microseconds** for a single AES evaluation — because the heavy cryptographic work was done offline.

For the Half-MPC protocol, this means:
- Hub pre-generates garbled circuits for future AES blocks during idle time
- When a Consumer request arrives, only the online phase runs (~0.5ms per request)

---

## 6. Protocol Design

### 6.1 Roles

| Role | Description |
|---|---|
| **Hub** | Central dispatch server. Receives Consumer requests, assigns them to Providers, verifies responses. Operated by the platform. |
| **Provider** | Holds an upstream API key/token. Establishes TCP connections to the upstream API using its own IP. Participates in MPC during TLS handshake and request encryption. |
| **Upstream API** | The LLM API server (e.g., `api.openai.com`). Unmodified; sees a standard TLS connection from the Provider's IP. |

### 6.2 Phase 0: MPC-TLS Handshake (One-Time Per Connection)

Hub and Provider jointly perform the TLS 1.3 handshake using 2-party computation (2PC). The TCP connection originates from the Provider's machine, so the upstream API sees the Provider's IP.

```
Hub (Verifier)           Provider (Prover)           api.openai.com
     |                        |                            |
     |                        |──TCP SYN──────────────────>|
     |                        |<─TCP SYN-ACK───────────────|
     |                        |──TCP ACK──────────────────>|
     |                        |                            |
     |<=== MPC channel =====>|                            |
     |                        |                            |
     |  Joint ECDH:           |                            |
     |  Hub inputs: a_H       |                            |
     |  Provider inputs: a_P  |                            |
     |  2PC computes:         |                            |
     |    a = a_H + a_P (mod n)                            |
     |    g^a = client's ECDH public key                   |
     |    shared_secret = (g^b)^a                          |
     |                        |                            |
     |                        |──ClientHello(g^a)────────> |
     |                        |<─ServerHello(g^b)────────── |
     |                        |<─{Certificate}───────────── |
     |                        |<─{CertificateVerify}─────── |
     |                        |<─{Finished}──────────────── |
     |                        |                            |
     |  Joint HKDF:           |                            |
     |  2PC derives traffic   |                            |
     |  secrets as XOR shares |                            |
     |                        |                            |
     |  Hub gets:             |  Provider gets:            |
     |    cts_H (client share)|    cts_P (client share)    |
     |    sts_H (server share)|    sts_P (server share)    |
     |                        |                            |
     |  Hub verifies server   |                            |
     |  certificate chain     |                            |
     |  (confirms connection  |                            |
     |   is to api.openai.com)|                            |
     |                        |                            |
     |                        |──{Finished}──────────────> |
     |                        |                            |
```

**MPC operations during handshake:**

1. **ECDH Key Exchange**: Hub holds private share `a_H`, Provider holds `a_P`. Via 2PC, they jointly compute the shared ECDH secret without either party learning the complete private key or the shared secret.

2. **HKDF Key Derivation**: The shared secret feeds into HKDF (which is HMAC-based). Via 2PC over the HMAC circuit, both parties obtain XOR shares of the resulting traffic secrets:

```
client_application_traffic_secret:
  Hub holds:      cts_H     (random 256-bit share)
  Provider holds: cts_P     (random 256-bit share)
  Actual secret:  cts = cts_H ⊕ cts_P

server_application_traffic_secret:
  Hub holds:      sts_H     (random 256-bit share)
  Provider holds: sts_P     (random 256-bit share)
  Actual secret:  sts = sts_H ⊕ sts_P
```

3. **Server Certificate Verification**: Hub verifies the server's certificate chain (ensuring the TLS connection is to `api.openai.com`, not an impostor). The certificate is part of the handshake transcript visible through the MPC protocol.

**Cost**: approximately 2-5 seconds (dominated by garbled circuit evaluation for ECDH scalar multiplication). Done **once per TLS connection**, amortized across all subsequent HTTP requests.

### 6.3 Phase 1: Asymmetric Key Distribution

This is the core insight of the Half-MPC design. After the MPC handshake, the **server traffic secret** is fully revealed to the Hub:

```
Provider ──sts_P──> Hub       (Provider sends its share of the server secret)

Hub computes:
  server_traffic_secret = sts_H ⊕ sts_P         (now Hub knows the complete secret)
  server_write_key = HKDF-Expand-Label(sts, "key", "", 16)
  server_write_iv  = HKDF-Expand-Label(sts, "iv", "", 12)
```

The **client traffic secret remains secret-shared**:

```
client_application_traffic_secret:
  Hub holds:      cts_H     (unchanged, random share)
  Provider holds: cts_P     (unchanged, random share)
  Neither party can reconstruct: cts = cts_H ⊕ cts_P
```

**Resulting key distribution:**

| Key material | Hub knows? | Provider knows? | Purpose |
|---|---|---|---|
| `client_traffic_secret` | Only its share `cts_H` | Only its share `cts_P` | Encrypting requests (client→server) |
| `server_traffic_secret` | ✅ Complete | ❌ Discarded its share | Decrypting responses (server→client) |

**Why this is safe**: As explained in §4.5, the client and server traffic secrets are independently derived from the Master Secret via separate HKDF-Expand-Label calls. Knowing the server traffic secret reveals nothing about the client traffic secret. The Provider's API key is protected by the client traffic secret, which remains split.

### 6.4 Phase 2: Request Encryption (Per Request)

When a Consumer request arrives, the Hub must construct an HTTP request and encrypt it as a TLS record. The HTTP request contains both **public fields** (known to Hub) and a **secret field** (the API key, known only to Provider).

#### HTTP Request Structure

```http
POST /v1/chat/completions HTTP/1.1\r\n       ← Hub knows
Host: api.openai.com\r\n                      ← Hub knows
Authorization: Bearer sk-proj-xxxx...\r\n     ← ONLY Provider knows
Content-Type: application/json\r\n            ← Hub knows
Content-Length: 142\r\n                        ← Hub knows
\r\n
{"model":"gpt-4o","messages":[...]}           ← Hub knows (Consumer's prompt)
```

#### AES Block Layout

When serialized and split into 16-byte AES-CTR blocks:

```
Block  0: "POST /v1/chat/c"       ← public (Hub knows plaintext)
Block  1: "ompletions HTTP"       ← public
Block  2: "/1.1\r\nHost: ap"      ← public
Block  3: "i.openai.com\r\n"      ← public
Block  4: "Authorization: "       ← public (header name)
Block  5: "Bearer sk-proj-"       ← SECRET (API key begins)
Block  6: "xxxxxxxxxxxxxxxx"      ← SECRET (API key body)
Block  7: "xxxx\r\nContent-"      ← SECRET (API key ends)
Block  8: "Type: applicatio"      ← public
Block  9: "n/json\r\nConten"      ← public
...
Block  N: "...prompt..}}\x17"     ← public (+ TLS content type byte 0x17)
```

Only **3-4 blocks** (48-64 bytes) contain API key material. A typical request has 30-50+ blocks total.

#### Encryption Protocol

**Step 1: Keystream generation for public blocks**

For blocks where Hub knows the entire plaintext (the majority of blocks):

```
2PC garbled circuit:
  Hub inputs:      cts_H, nonce, counter_i
  Provider inputs: cts_P

  Circuit computes internally:
    client_key = cts_H ⊕ cts_P           // reconstruct key inside circuit
    keystream[i] = AES(client_key, nonce ∥ counter_i)

  Output → both parties receive keystream[i]
  (This is safe: Hub knows the plaintext for these blocks, so the keystream
   combined with Hub's known plaintext reveals nothing new to Hub.
   Provider already knows its own key share.)

Hub computes locally:
  ciphertext[i] = known_plaintext[i] ⊕ keystream[i]
```

**Step 2: Encryption for secret blocks (containing API key)**

For blocks 5-7 (containing the API key):

```
2PC garbled circuit:
  Hub inputs:      cts_H, nonce, counter_i, header_template[i]
                   (e.g., "Bearer " padding or "\r\nContent-" suffix)
  Provider inputs: cts_P, api_key_bytes[i]
                   (the API key bytes for this block position)

  Circuit computes internally:
    client_key = cts_H ⊕ cts_P
    plaintext[i] = merge(header_template[i], api_key_bytes[i])
    keystream[i] = AES(client_key, nonce ∥ counter_i)
    ciphertext[i] = plaintext[i] ⊕ keystream[i]

  Output → ciphertext[i] goes to Hub ONLY
```

**Why Hub cannot recover the API key**:
- Hub receives `ciphertext[i]` but NOT `keystream[i]` for secret blocks
- Hub does not know `cts_P`, so it cannot compute `client_key` or `keystream[i]` locally
- Without `keystream[i]`, Hub cannot reverse `ciphertext[i] ⊕ keystream[i]` to get `plaintext[i]`
- Therefore, the API key bytes inside `plaintext[i]` remain hidden from Hub

**Step 3: GCM authentication tag**

```
2PC garbled circuit:
  Hub inputs:      cts_H, nonce
  Provider inputs: cts_P

  Circuit computes:
    client_key = cts_H ⊕ cts_P
    H = AES(client_key, 0^128)             // hash subkey for GHASH
    J0 = AES(client_key, nonce ∥ 0^32)     // mask for final tag XOR

  Output → H and J0 to Hub only

Hub computes GHASH locally (it's a public polynomial evaluation over the ciphertext):
  tag = GHASH(H, AAD, all_ciphertext_blocks) ⊕ J0
```

GHASH is computed locally because it operates on the ciphertext (which Hub now has for all blocks) and H/J0 (which the circuit outputs to Hub). No private inputs are needed.

**Step 4: Assemble and forward**

```
Hub assembles the complete TLS record:
  record = TLS_header(5 bytes) ∥ all_ciphertext_blocks ∥ tag(16 bytes)

Hub ──record bytes──> Provider ──TCP socket.write()──> api.openai.com
```

The Provider simply writes the raw bytes to its TCP connection. It does not parse, decrypt, or inspect the TLS record. The upstream API receives a perfectly valid TLS record from the Provider's IP address.

### 6.5 Phase 3: Response Decryption (Per Request)

The upstream API encrypts its response with the **server write key** and sends it back through the Provider's TCP connection:

```
api.openai.com ──encrypted TLS records──> Provider ──TCP forward──> Hub
```

The Provider forwards the raw ciphertext bytes to the Hub without any processing.

**The Hub decrypts locally — no MPC involved:**

```
For each received TLS record:

  1. Parse the record header (5 bytes) to get the payload length
  2. Separate the payload into ciphertext and tag (last 16 bytes)
  3. Construct the nonce:
       nonce = server_write_iv ⊕ sequence_number
  4. Verify and decrypt:
       plaintext = AES-GCM-Decrypt(server_write_key, nonce, AAD, ciphertext, tag)

  If tag verification FAILS:
    → The record was tampered with (Provider modified the ciphertext in transit)
    → Reject the response and flag the Provider

  If tag verification PASSES:
    → The plaintext is guaranteed to be exactly what api.openai.com sent
    → No modification is possible without breaking the tag
    → Extract the HTTP response data (including SSE stream chunks)
```

**This is why it's "Half-MPC"**: response decryption has **zero MPC cost**. The Hub holds the complete server traffic key and decrypts independently. Since LLM responses are typically much larger than requests (hundreds to thousands of tokens across many TLS records), eliminating MPC from the response path removes the majority of the computational overhead.

For **SSE streaming** (Server-Sent Events, the standard format for LLM streaming responses):
- Each SSE chunk may span one or more TLS records
- The Hub decrypts each TLS record as it arrives, with no buffering delay
- The decrypted chunks are forwarded to the Consumer in real-time
- Latency is identical to a direct connection (zero MPC overhead on this path)

### 6.6 Phase 4: Verification & Settlement

After each request-response cycle, the Hub possesses:

1. The Consumer's original prompt (Hub constructed the request)
2. The **verified, decrypted** response from the upstream API (decrypted with the server key; tag verification proves authenticity)
3. Proof that the TLS connection is to `api.openai.com` (server certificate verified during MPC handshake in Phase 0)
4. Response metadata including `x-request-id`, `openai-processing-ms`, and `usage` fields from the upstream API

The Hub can:
- **Forward** the verified response to the Consumer
- **Meter** token usage from the response's `usage` field (input_tokens, output_tokens)
- **Bill** the Consumer and credit the Provider accordingly
- **Log** verification outcomes for audit and dispute resolution

---

## 7. Why "Half-MPC"

The protocol applies MPC selectively to only one direction of data flow:

```
                    MPC required?     Why?
                    ─────────────     ────
Request direction
(client → server):  ✅ YES           Client key is secret-shared;
                                     API key is Provider's private input.
                                     MPC ensures neither party can
                                     unilaterally construct requests.

Response direction
(server → client):  ❌ NO            Server key is fully held by Hub.
                                     Hub decrypts and verifies
                                     responses independently.
                                     Provider only forwards ciphertext.
```

This asymmetry is possible because TLS 1.3 derives **independent keys for each direction** (§4.5). Revealing the server→client key to the Hub does not compromise the client→server key.

**Security implications of this asymmetry:**

| Capability | Hub | Provider |
|---|---|---|
| Decrypt server responses | ✅ (has server key) | ❌ (no key) |
| Forge server-direction TLS records | ✅ theoretically | ❌ |
| Construct client-direction TLS records | ❌ (only has client key share) | ❌ (only has client key share) |
| Learn the API key | ❌ (protected by MPC in client direction) | ✅ (it's their key) |
| Verify response authenticity | ✅ (GCM tag check with server key) | ❌ (no key to verify) |

The Hub's ability to forge server-direction records is not a practical concern: the Provider never inspects or verifies server-direction records (it only forwards raw bytes), and the Hub has no incentive to forge responses to its own Consumers.

---

## 8. Security Analysis

### 8.1 Provider Attacks

| Attack | Prevented? | Mechanism |
|---|---|---|
| Substitute a cheaper model | ✅ | Hub decrypts the verified response and checks the model field, response timing, and content characteristics |
| Modify Consumer's prompt | ✅ | Hub constructs the request plaintext (except API key); any modification breaks the GCM tag at the upstream server |
| Tamper with the upstream response | ✅ | Hub verifies GCM authentication tags using the server key; any bit flip in transit is detected |
| Fabricate a response without calling the API | ✅ | Provider does not have the server key; cannot create valid GCM-tagged records |
| Redirect to a different API server | ✅ | Server certificate verified during MPC handshake; Hub confirms server identity is `api.openai.com` |
| Replay a previous response | ✅ | TLS sequence numbers increment monotonically; replayed records have wrong nonces and fail tag verification |

### 8.2 Hub Attacks

| Attack | Prevented? | Mechanism |
|---|---|---|
| Learn the Provider's API key | ✅ | Client key is secret-shared; API key blocks encrypted inside 2PC circuit; Hub receives ciphertext but not keystream |
| Use Provider's API key independently | ✅ | Hub cannot construct valid client-direction TLS records without Provider's key share |
| Fabricate a response to Consumer | ❌ (trusted) | Hub could theoretically construct fake server records (has the key), but this undermines its own platform reputation |
| Eavesdrop on Consumer's prompt | ⚠️ Inherent | Hub constructs the HTTP request body — it necessarily sees the prompt. Prompt privacy requires additional measures (e.g., TEE on Hub side) |

### 8.3 External Attacks

| Attack | Prevented? | Mechanism |
|---|---|---|
| Network eavesdropping | ✅ | Standard TLS encryption on the Provider↔API path; Hub↔Provider MPC channel uses its own encryption |
| Man-in-the-middle | ✅ | Server certificate verification during handshake (Hub verifies the certificate chain) |
| Replay attacks | ✅ | TLS sequence numbers; fresh nonces per record |

---

## 9. Performance Analysis

### 9.1 MPC Operation Costs

AES-128 implemented as a boolean circuit requires approximately **6,400 AND gates** (XOR gates are free under the Free-XOR optimization).

| Operation | AES evals | AND gates | Estimated time |
|---|---|---|---|
| **Phase 0**: ECDH + HKDF (one-time per connection) | N/A | ~500,000 | 2-5 seconds |
| **Phase 2**: Public block keystream (per block) | 1 | 6,400 | ~0.05ms |
| **Phase 2**: Secret block encryption (per block) | 1 | 6,400 | ~0.05ms |
| **Phase 2**: GCM H and J0 derivation (per record) | 2 | 12,800 | ~0.1ms |
| **Phase 3**: Response decryption (per record) | 0 (local AES) | 0 | ~0ms MPC cost |

### 9.2 Per-Request Cost Breakdown

For a typical LLM API request (30 public blocks + 4 secret blocks + GCM tag computation):

```
Request encryption MPC:  (30 + 4) × 0.05ms + 0.1ms ≈ 1.8ms
Response decryption:     0ms (Hub decrypts locally)
──────────────────────────────────────────────────────
Total MPC overhead:      ~2ms per request
```

With offline precomputation (garbled circuits generated during idle time):

```
Online-only overhead:    ~0.5ms per request
```

### 9.3 End-to-End Latency Impact

| Component | Latency | On critical path? |
|---|---|---|
| MPC-TLS handshake (Phase 0) | 2-5 seconds | No (pre-warmed in connection pool) |
| Request encryption MPC (Phase 2) | ~2ms (or ~0.5ms with precomputation) | Yes |
| Response decryption (Phase 3) | ~0ms extra | No (Hub decrypts locally as fast as normal TLS) |
| LLM inference at upstream API | 500ms – 30s | Yes (baseline, unavoidable) |
| **Effective overhead** | **~2ms** | **Negligible vs LLM inference time** |

### 9.4 Bandwidth Overhead

| Channel | Extra bandwidth |
|---|---|
| Hub ↔ Provider (MPC) | ~200KB per handshake; ~50KB per request (garbled circuits). With precomputation: ~5KB online per request. |
| Provider ↔ Upstream API | Zero (standard TLS; Provider is just forwarding bytes) |
| Hub → Consumer | Zero (standard HTTP response forwarding) |

---

## 10. Connection Pool & Lifecycle

### 10.1 Pre-Warming

To hide handshake latency from the request path, the Hub maintains a pool of pre-established MPC-TLS connections:

```
Hub startup / background loop:
  For each registered Provider:
    1. Establish 2 MPC-TLS connections (background, not blocking requests)
    2. Pre-generate garbled circuits for the next ~100 AES block evaluations

When a Consumer request arrives:
    1. Pick an idle, pre-warmed connection from the pool for the target Provider
    2. Use pre-generated garbled circuits for request encryption (online phase only)
    3. Process the request
    4. Return the connection to the pool
    5. Background: replenish garbled circuit stock for future requests

If no pre-warmed connection is available:
    Establish a new MPC-TLS connection (2-5s delay on this first request)
```

### 10.2 Connection Lifecycle

```
            MPC Handshake (2-5s, one-time)
                       │
                       ▼
┌──── Active TLS Connection (reused) ────┐
│                                         │
│  Request 1 → MPC encrypt → forward     │
│  Response 1 ← Hub decrypt ← forward   │
│                                         │
│  Request 2 → MPC encrypt → forward     │
│  Response 2 ← Hub decrypt ← forward   │
│                                         │
│  ...                                    │
│                                         │
│  Maintenance:                           │
│  • Idle timeout: 60s (close if unused)  │
│  • Key Update: every 100 reqs or 5min  │
│  • Max lifetime: 30min                  │
│  • Error recovery: close + re-establish │
│                                         │
└─────────────────────────────────────────┘
                       │
                       ▼
              Connection closed
          (new one pre-warmed in background)
```

### 10.3 Key Update Handling

When a TLS Key Update is triggered (either by the server or proactively by the Hub):

**Client traffic secret update** (secret-shared):

```
Hub and Provider run a lightweight 2PC-HMAC:

  2PC inputs:
    Hub:      current cts_H
    Provider: current cts_P

  2PC computes:
    current_cts = cts_H ⊕ cts_P
    new_cts = HKDF-Expand-Label(current_cts, "traffic upd", "", 32)
    new_cts_H = random()
    new_cts_P = new_cts ⊕ new_cts_H

  Outputs:
    Hub gets:      new_cts_H
    Provider gets: new_cts_P

Cost: ~1ms (one HMAC circuit, much smaller than AES)
```

**Server traffic secret update** (Hub holds complete):

```
Hub computes locally:
  new_sts = HKDF-Expand-Label(current_sts, "traffic upd", "", 32)
  new_server_write_key = HKDF-Expand-Label(new_sts, "key", "", 16)
  new_server_write_iv  = HKDF-Expand-Label(new_sts, "iv", "", 12)

Cost: ~0ms (local HMAC, no MPC)
```

---

## 11. Comparison With Alternative Approaches

| Dimension | Self-signed receipt | TEE attestation | Full MPC-TLS | Proxy Mode | **Half-MPC (this)** |
|---|---|---|---|---|---|
| **Proves response origin** | ❌ Self-attested | ✅ Hardware | ✅ Crypto | ✅ ZK proof | ✅ Crypto |
| **Special hardware** | None | Intel TDX + NVIDIA CC | None | None | **None** |
| **API key privacy** | N/A | ✅ In enclave | ✅ Shared | ⚠️ Mode-dependent | **✅ Secret-shared** |
| **Upstream sees** | Provider IP | Provider IP | Provider IP | Hub IP ❌ | **Provider IP ✅** |
| **Per-request overhead** | ~0ms | ~0ms | ~seconds | ~0ms online | **~2ms** |
| **Response decryption** | ~0ms | ~0ms | ~seconds ❌ | ~0ms | **~0ms (local)** |
| **Handshake cost** | None | ~30s attestation | Per request ❌ | Per connection | **Per connection (amortizable)** |
| **Trust assumption** | Trust Provider | Trust HW vendor | Minimal | Trust proxy + ZK | **Trust Hub for delivery** |
| **Engineering effort** | Low | High (HW + ops) | Very High | High (ZK) | **Medium** |

### Key Advantages Over Full MPC-TLS

1. **Response decryption is free**: No MPC for the server→client direction. LLM responses (the bulk of data) incur zero MPC overhead.
2. **Simpler circuits**: Only AES encryption circuits are needed, not the full TLS record processing state machine.
3. **Better streaming**: Hub decrypts SSE chunks locally as they arrive — no MPC round-trips per chunk.

### Key Advantages Over TEE

1. **No hardware requirements**: Any commodity server or cloud instance works.
2. **No vendor trust**: No need to trust Intel/AMD's TEE implementation or firmware update process.
3. **Cryptographic guarantees**: Security follows from mathematical hardness assumptions (ECDH, AES), not from hardware correctness.

### Key Advantages Over Proxy Mode

1. **Provider IP preserved**: Upstream API sees Provider's IP, not Hub's. No account-ban risk.
2. **API key privacy**: Hub cannot learn Provider's API key.

---

## 12. Implementation Notes

### 12.1 Recommended Tech Stack

| Component | Technology | Rationale |
|---|---|---|
| Hub server | Go | Existing codebase; high-performance networking |
| Provider App | Go | Existing codebase; TCP forwarding is trivial in Go |
| MPC library | Rust (`mpz` / `tlsn` crates) | TLSNotary's battle-tested 2PC primitives for TLS |
| Go ↔ Rust bridge | Subprocess or FFI (cgo) | MPC module runs as a Rust sidecar process |
| MPC transport | WebSocket (existing Hub↔Provider channel) | Reuse existing infrastructure |

### 12.2 Integration With TLSNotary

The `tlsn` crate (TLSNotary's Rust implementation) already provides:

- 2PC-AES garbled circuit implementations (optimized with Free-XOR and half-gates)
- Oblivious Transfer extensions (IKNP protocol)
- TLS 1.3 MPC handshake protocol
- HKDF and HMAC MPC circuits

The Half-MPC protocol can be built by:

1. **Reusing** `tlsn`'s MPC-TLS handshake module for Phase 0
2. **Modifying** the post-handshake phase to reveal `server_traffic_secret` to the Hub (Phase 1 — a small protocol change)
3. **Using** `tlsn`'s 2PC-AES primitives for per-block request encryption (Phase 2)
4. **Implementing** standard AES-GCM decryption in Go (Phase 3 — no MPC library needed)

### 12.3 Provider App Changes

The Provider App's role simplifies significantly:

**New responsibilities:**
1. TCP connection management: establish and maintain TCP connections to the upstream API
2. MPC participation: run the Rust MPC sidecar for handshake and request encryption
3. Byte forwarding: relay TLS record bytes between Hub and upstream API (`io.Copy` in Go)

**No longer needed:**
- HTTP request/response parsing (Hub handles this)
- TLS library usage (Hub drives TLS through MPC; Provider just forwards bytes)
- Direct API key usage in HTTP headers (key is injected via MPC circuit)

### 12.4 Phased Rollout

The protocol can be deployed incrementally:

**Phase 1 — Baseline (deploy first):**
Use the simpler "Wokey" model where Hub holds full TLS keys and Provider's API key. This validates the TCP-tunnel architecture and business model with zero MPC complexity.

**Phase 2 — Half-MPC (deploy when API key privacy matters):**
Upgrade to the full Half-MPC protocol. The TCP tunnel architecture from Phase 1 remains unchanged. The only addition is the MPC sidecar on both Hub and Provider, which handles key sharing and request encryption. Provider App changes are minimal (add sidecar process management).

**Phase 3 — Probabilistic sampling (optional optimization):**
For maximum throughput, use Half-MPC verification on a random sample (e.g., 5%) of requests. Non-sampled requests use the simpler Wokey model. Combined with a staking/slashing mechanism, this maintains economic deterrence against cheating while reducing steady-state MPC overhead to near-zero.

---

## 13. Limitations & Future Work

### 13.1 Current Limitations

1. **Prompt privacy**: The Hub sees the Consumer's prompt (it constructs the HTTP request). Full prompt privacy would require either full MPC-TLS (both directions) or a TEE on the Hub side (e.g., AWS Nitro Enclave).

2. **Hub trust for response delivery**: While the Hub cryptographically verifies responses, the Consumer must trust the Hub to relay them faithfully. A malicious Hub could theoretically suppress or substitute responses (using the server key it holds). Mitigation: make verification commitments independently auditable.

3. **Connection overhead**: Each Provider requires pre-established MPC-TLS connections. With hundreds of Providers, pool management becomes non-trivial. Connection warm-up failures should be handled gracefully.

4. **Upstream API compatibility**: The protocol assumes TLS 1.3 with AES-GCM. If the upstream API negotiates a different cipher suite (e.g., ChaCha20-Poly1305), the MPC circuits must support that cipher. TLS 1.2 requires different handling (separate MAC keys vs. AEAD).

### 13.2 Future Enhancements

1. **On-chain dispute resolution**: Publish verification commitments (hash of verified response + metadata) on-chain. In case of disputes, the MPC transcript provides cryptographic evidence.

2. **ZK proof of verification**: After verifying a response, the Hub generates a succinct ZK proof that the verification was performed correctly. This removes the Consumer's trust dependency on the Hub.

3. **Model fingerprinting integration**: Combine TLS binding (proves bytes came from the upstream API) with black-box model fingerprinting (proves the upstream API served the claimed model, not a cheaper substitute). TLS binding handles transport-layer attribution; fingerprinting handles application-layer model identity.

4. **LLM pricing oracle**: Aggregate upstream API pricing data on-chain. Provider pricing can be validated against oracle reference prices, adding an economic fairness layer.

---

*Document version: 2.0*
*Last updated: August 2026*
