# TLS 1.3 选择性 MPC 引擎

已接入共享 sidecar、Go 能力协商、路由和预热池。两端 sidecar 显式设置 `--tls-version 1.3`，Go route 设置 `tls_version: "1.3"`；省略时仍使用 TLS 1.2，版本不匹配立即拒绝，无自动降级。保留 Provider 实际写入 ACK、规范请求校验和结算绑定。Go SDK 调用方式不变，配置见 [业务接入指南](../../../docs/business-integration-zh.md)。

TLS 1.3 新进程未指定 `--capacity` 时默认共享 `5m` 档位；Go route 必须匹配精确容量，参见 [示例配置](../../../config/hub-tls13.example.json)。所有较小请求可共用该池，凭证电路仍最多 1 KiB；显式旧 capacity 继续支持。TLS 1.2 默认 baseline 不变。

密钥计划复用当前 VM、同一 HMAC key 的秘密前缀压缩状态，减少重复 HKDF 电路求值，不复用会话或 OT 随机材料。此执行计划使用 MPC schedule revision 2，并要求 `tls13-keyed-hmac-state` 能力；新旧 sidecar 必须在秘密输入之前拒绝混用，升级需排空后成对更新。外层 RPC 仍为 v1，详见 [ADR 0007](../../../docs/adr/0007-session-local-hmac-prefix-states.md)。

## 已实现的协议范围

- TLS 1.3、P-256、TLS_AES_128_GCM_SHA256；完整握手，无自动降级。
- 两方 ECDHE、SHA-256/HMAC/HKDF 电路，证书链、DNS、CertificateVerify 和 Finished 校验。
- HTTP/1.1 ALPN；未返回 ALPN 时仍按 HTTP/1.1 处理。
- 旧客户端应用密钥只用于凭证前缀和 KeyUpdate，均通过两方计算得到密文。
- 两条旧密钥记录得到上游投递确认后，才向 Hub 输出下一代客户端 traffic secret。后续正文由 Hub 本地 AES-GCM 加密，按最多 512 KiB 批次转发。
- 服务端响应由 Hub 认证解密，支持握手消息分片、NewSessionTicket 的有界解析和丢弃、服务端主动 KeyUpdate 及其应答。
- 独立管理每个方向、每代密钥的隐式记录序号；认证失败后禁止继续使用该方向。
- 一会话一请求；最大请求 5 MiB，最大响应密文总量 16 MiB，凭证前缀（含 inner type）最多 1024 字节。

不支持 PSK、0-RTT、恢复会话、HelloRetryRequest、客户端证书、HTTP/2、其他曲线或加密套件。遇到这些情况会拒绝，不切换到普通 TLS 或 TLS 1.2。一般 TLS 1.3 支持并不意味着所有上游都与该受限配置兼容。

## 角色和输出认证

此模块让 **Hub 生成混淆电路，Provider 求值**。目标信任边界是 Hub 遵守协议、Provider 可以偏离协议；不能用于主动恶意 Hub 的安全承诺。

使用现有 MPZ KOS OT、混淆电路和输出 MAC 校验。需要只交给 Hub 的值先在电路内与 Hub 独有的新随机掩码异或，再走正常的带 MAC 证明的解码流程。Provider 只能得到被掩码保护的值，Hub 验证输出证明后去掉掩码。每次输出使用独立掩码。本模块不使用 DEAP 的延迟验证，也不使用未经输出认证的单向解码捷径。

凭证电路只将 Provider 输入槽中指定的 credential span 接入输出，其余 HTTP 前缀和 inner content type 来自 Hub。电路还验证凭证每个字节均为 0x21–0x7e，拒绝换行、空格、控制字符和非 ASCII，防止跨 HTTP 头注入。Provider 即使改变自己的槽外输入，也不能改变这些字节。

旧客户端应用 traffic secret、AES key 和凭证位置 keystream 不输出给任一方；Hub 会得到旧记录的 GHASH 子密钥及两条记录各自的 tag mask。这个设计明确依赖 Hub 遵守协议，不能据此宣称能阻止恶意 Hub 伪造旧记录。Hub 获得新代客户端密钥后也不再需要 Provider 对每个正文记录联合授权。Provider 不得到服务端解密密钥或新代客户端密钥。

这些是实现结构及测试覆盖，不是完整密码协议的形式化证明或独立审计。跨进程适配保留上游投递 ACK 和请求/结算绑定；这些业务层保证由四进程验收另行覆盖。

## 调用约束

入口为 `hub_handshake`、`provider_handshake` 和 `Policy`。完整调用示例见 [tests/real.rs](tests/real.rs)。

1. 调用方认证两方的 MPC 通道，分别传入对应的 `DuplexStream`。
2. 两端并发执行握手，并设置外部超时。Hub 提供根证书和明文响应输出通道，Provider 提供上游流。
3. 两端先独立校验规范 HTTP 请求、模型及请求哈希，再并发调用 `request`。两方传入相同的零凭证模板与 span，只有 Provider 传入真实凭证。
4. Hub 调用 `response`，业务同时消费输出并校验完整 HTTP 消息。响应大于 duplex 缓冲区时必须并发排空；提前消费部分响应不等于请求已经成功结算。
5. 任意错误或取消均销毁会话；Provider 必须保持存活直到 Hub 读完响应。

Provider 上游流的 `flush()` 必须意味着数据已经实际投递到上游；如果流只是另一个进程的内存缓冲区，必须用现有 delivery ACK 封装。这个条件是密钥释放顺序的一部分。库本身不替调用方做 TCP/DNS 出站策略、HTTP 业务校验、重试、超时或结算。

## 验证

在仓库根目录运行：

```sh
cargo test --manifest-path rust/Cargo.toml --release -p tokenhive-tls13
cargo test --manifest-path rust/Cargo.toml --release -p tokenhive-tls13 --test real -- --ignored --nocapture --test-threads=1
cargo clippy --manifest-path rust/Cargo.toml -p tokenhive-tls13 --all-targets -- -D warnings
```

常规测试包括 RFC 8448 HKDF 向量、MPC 与本地密钥派生比对、真实 OT 的独立输出掩码、伪造输出 MAC 拒绝、凭证槽外输入隔离、GCM tag 独立比对、记录篡改/重放、密钥更新和解析边界。

真实互操作测试使用独立 rustls TLS 1.3 服务端和真实两方 MPC，覆盖 4 KiB、16 KiB、64 KiB、256 KiB、1 MiB、5 MiB 请求，双方主动 KeyUpdate、单次使用、错误 DNS 和请求模板不一致时没有应用数据投递。测试不调用外部 API，也不使用业务凭证。

参考：[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)、[RFC 8448](https://www.rfc-editor.org/rfc/rfc8448.html)。

2026-10-27 验证结果：库测试、1 项输出认证测试以及 2 项真实互操作测试通过；Rust 工作区测试、Clippy（`-D warnings`）和格式检查通过。真实测试显式使用了 `--ignored`，不是仅完成编译。

下面是 2026-10-27 Apple M3 Pro 同机 loopback、每档一次的最终构建样本；在线时间包含凭证 MPC、KeyUpdate、请求正文实际写入测试 TCP 流，不包含模型推理或首 token 等待，也不是跨机 RTT、P95/P99 或四进程业务基准。

| 请求容量 | 预热 | 在线请求发送 |
|---|---:|---:|
| 4 KiB | 79.0 ms | 1.8 ms |
| 16 KiB | 71.9 ms | 2.0 ms |
| 64 KiB | 73.6 ms | 2.4 ms |
| 256 KiB | 96.3 ms | 8.1 ms |
| 1 MiB | 74.4 ms | 13.5 ms |
| 5 MiB | 72.9 ms | 59.6 ms |

四进程接入验收已通过显式 TLS 1.3 baseline 和共享 5 MiB 容量（5,241,856 字节 prompt），覆盖 JSON/SSE、Go SDK、投递 ACK、幂等与回执；默认 TLS 1.2 回归也通过。执行 `make smoke-tls13` 或 `make smoke-tls13-large` 可重现，详情见 [集成验收记录](../../../docs/integration-validation.md)。上述性能表仍为独立引擎样本，不代表四进程延迟。

最新四进程 profile 对照、最终构建及未验证边界见 [2026-10-27 优化报告](../../../docs/performance/optimization-2026-10-27.md)。
