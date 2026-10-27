# TokenHive MPC Capacity Baseline

Measured on 2026-08-27 with an AMD EPYC 7R13 CPU. Both MPC parties, the TLS
fixture, and the Provider delivery relay ran in one process on one host. Builds
used Cargo's optimized `release` profile.

Run the reproducible matrix with:

```sh
./scripts/benchmark-mpc-capacity.sh
```

The default matrix runs three fresh sessions for each request size and applies
a 30-second outer timeout to every sample. The default protocol-v1 profile is
4 KiB of request plaintext.

| Request plaintext | Successful request delivery | Successful handshake |
|---:|---:|---:|
| 797 bytes | 12-13 ms | 618-622 ms |
| 1,822 bytes | 26-27 ms | 616-633 ms |
| 3,358 bytes | 48-51 ms | 623-633 ms |
| 3,786 bytes | 55 ms | 620-629 ms |

Request delivery measures Provider selective MPC encryption through the
matching upstream socket delivery ACK. Handshake setup is intended to be
amortized by a connection pool. Canonical Go request construction remained
below 0.1 ms at all tested sizes and is not the bottleneck.

One of 12 release matrix samples hit the outer handshake timeout. Successful
latencies are stable and request cost is approximately linear. The runtime now
uses longer bounds for opt-in large-profile preprocessing, but the underlying
intermittent TLSNotary/MPZ stall still needs to be eliminated or bounded.

The public-record path was also exercised end to end with a 16,700-byte
canonical request spanning two TLS application records. The first record
overlapped the credential and used selective encryption; the second was
body-only and used decoded preprocessed keystream. Three same-host release
samples completed preprocessing and handshake in 2.022-2.039 seconds and
delivered the request in 257-293 ms:

```sh
cd rust
TOKENHIVE_MPC_TEST_PUBLIC_BODY=1 cargo test --release -p tokenhive-sidecar \
  attached_channels_run_real_selective_mpc_tls_request -- --ignored --nocapture
```

This verifies record transition, canonical-template enforcement, and wire
interoperability. It is a single regression sample, not a 5 MiB capacity
benchmark or a production SLO. Before admitting the 5 MiB profile, measure a
full-size request on deployment hardware and network, including warm latency,
peak memory, p50/p95/p99, failure rate, and concurrent-session throughput.

These same-host numbers exclude WAN RTT, Provider egress variability, upstream
service latency, and concurrent-session contention. They are a regression
baseline, not a production SLO.

The authenticated Consumer streaming layer was benchmarked independently on
the same host. Relaying 256 validated SSE JSON events plus final usage and
`[DONE]` (about 26 KiB) took 2.9 ms per response at 9.0 MB/s. This includes
HTTP parsing, duplicate-key JSON validation, stable model/ID accumulation,
usage validation, hashing, receipt emission, and downstream writes:

```sh
go test ./internal/gateway -run '^$' -bench BenchmarkRelayOpenAISSE -benchmem
```

## Transport pipeline experiment (2026-10-24)

On AMD EPYC 7R32, an isolated Go tunnel benchmark imposes a synthetic 10 ms
delivery-ACK delay and sends 32 consecutive 1 KiB blocks. Both modes wait for
final delivery. Three samples per mode measured 325.3–326.4 ms with per-write
ACK waits and 40.9–41.2 ms with the eight-frame window. This isolates transport
serialization; it is not an end-to-end MPC/API speedup or a WAN SLO.

```sh
go test ./internal/tunnel -run '^$' -bench BenchmarkDeliveryPipeline -benchtime=1x -count=3
```

The separate TLS 1.3 wire experiment and its limitations are documented in
[performance-design-zh.md](performance-design-zh.md).

## TLS 1.2 client AES moved into warming (2026-10-24)

The authenticated two-party sidecar fixture now evaluates all configured client
CTR blocks and J0 tag masks before READY. The same 4 KiB capacity and 3,358-byte
canonical request (3,148-byte JSON body) produced these release-build samples:

| Implementation | Samples | Warm handshake | Online request delivery |
|---|---:|---:|---:|
| Before client AES preevaluation | 1 | 1,208 ms | 93 ms |
| With client AES preevaluation | 3 | 1,187–1,214 ms | 29–31 ms |

The online measurement ends at the Provider upstream-delivery ACK. These are
same-host regression samples; the single earlier sample is not enough for a
statistical speedup claim. They exclude WAN RTT and upstream inference, and the
change shifts computation into warming rather than removing its total cost.

A real two-record request also passed: 18,432-byte capacity, 17,695-byte canonical
request, 3,922 ms handshake, 158 ms online delivery. The arbitrary 18 KiB capacity
is an internal integration-test limit, not an advertised production profile.
The 16 KiB boundary, shortened tail and early-close cases additionally compare
ciphertext and tags against independent AES-GCM in ideal-VM tests.

Reproduce the 4 KiB measurement:

```sh
cd rust
TOKENHIVE_MPC_BENCH_PAD_BYTES=3072 cargo test --release -p tokenhive-sidecar \
  attached_channels_run_real_selective_mpc_tls_request -- --ignored --nocapture
```

Before this change, the 64 KiB capacity / 64,512-byte padding comparison process
was terminated with SIGKILL on this approximately 4 GiB, no-swap environment.
The available evidence does not identify the kill source. No completed 64 KiB–5 MiB
full-size MPC benchmark is claimed for this round; these profiles still need
resource and concurrency validation on deployment hardware. The TLS 1.3 Python
probe's large-body results do not fill that gap.


## 2026-10-24：真实四进程压测

新增公开 Go SDK → Go Hub → 两端 Rust sidecar / Provider Agent → 合成 HTTPS 上游的持续压测，覆盖固定并发、固定到达速率、JSON/SSE、1 MiB/5 MiB prompt、数据通道双向各 5 ms 延迟、CPU/RSS 和回执核对。发现并修复空预热池等待者互相唤醒导致的 CPU 空转。

本机 2 CPU 条件下，修复后小请求稳态约 1.37 请求/秒；1 RPS 到达的 JSON P95 约 278 ms（含上游固定 200 ms），过载时仍有秒级长尾和超时。详细方法、全部错误、前后对照和原始数据见 [压测报告](performance/e2e-2026-10-24.md)。早期独立引擎微基准不等于这些业务端到端指标。


## 2026-10-26 FIFO / 有界等待复测

已完成每池公平排队、有界等待和补库存通知竞态修复，复跑相同 15 场景，另做显式过载配置验证。小请求 4/8 并发 JSON P95 从 11.55/19.66 秒降为 3.08/6.29 秒；对应场景本轮无拒绝，持续吞吐约 1.37 请求/秒，未明显提升。中位等待上升，反映库存分配更公平。完整成功/失败/未发送计数、全部容量、附加链路延迟、CPU/RSS、原始样本和结算核对见 [完整报告](performance/e2e-2026-10-26.md)。
