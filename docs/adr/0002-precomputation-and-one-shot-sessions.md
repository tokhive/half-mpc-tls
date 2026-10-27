# ADR 0002：预处理库存与一次性会话

日期：2026-10-27。状态：已接受。模型：Hub 遵守协议，Provider 可以恶意。

## 决策

当前两个 TLS 引擎继续一会话一请求，不通过提高池的 `MaxUses` 开启连接复用。完成两层库存的可行性评估，但暂不将未测量的独立材料池作为默认生产路径。可复用的公开电路描述与一次性秘密材料分开讨论：前者可以缓存，后者始终只能由原来的双方会话独占消费。

这不是 TLS 标准禁止持久连接，而是本实现的秘密归属、记录预算与状态机共同形成的约束。

## 两层库存确实存在一个可拆分位置

TLS 1.2 的 [`Prover::commit`](../../rust/vendor/tlsn/src/prover.rs) 和 [`Verifier::accept`](../../rust/vendor/tlsn/src/verifier.rs) 都先执行 `deps.setup()`，随后 Provider 才 `connect` 上游。[双方依赖初始化](../../rust/vendor/tlsn/src/deps/prover.rs)会分配 VM 引用、设置协议角色、预处理 MPC，并配对单向服务器密钥输出。其[底层预处理](../../rust/vendor/tlsn-mpc-tls/src/leader.rs)并行执行密钥交换准备、记录层准备和 VM 预处理。故可以在不开上游 TCP 连接时保留一对已经完成 commit/accept 的活跃上下文。

TLS 1.3 也有较早的准备阶段：[`Party::new`](../../rust/crates/tls13/src/mpc.rs)建立角色、OT/VM 状态及凭证输入引用，执行密钥交换 setup；但服务器公钥、握手 transcript、ECDHE 份额、HKDF 和旧客户端 AES 求值依赖后续握手，不能全部提前到无上游阶段。[握手实现](../../rust/crates/tls13/src/engine.rs)中 `exchange`、`application` 和 `WarmPrefix::new` 的顺序直接体现这种依赖。

因此，若未来拆分，应区分：

| 库存 | 已准备内容 | 尚不能宣称的性质 |
| --- | --- | --- |
| PREPARED | 双方已配对的 MPC 协议/OT/VM 上下文，TLS 1.2 已完成 commit/accept | 不是通用可互换的随机字节包，不是已认证 TLS 连接 |
| READY | 已完成上游身份与 Finished 校验、具备一次性请求能力的活跃会话 | 不保证真实上游无限期保持空闲连接 |

这两个阶段仍绑定参与方、角色、协议与能力、VM 引用、资源预算和传输生命周期。当前代码没有提供可安全序列化、克隆或跨进程恢复秘密上下文的 Interface。不能因为应用请求尚未到达，就把这些秘密材料当成可重复使用或永不过期的库存。[现有池](../../internal/precompute/pool.go)明确保留 MaxIdle、MaxLifetime、健康淘汰和一次性消费约束；这些约束适用于任何后续库存分层。

## 为什么现在不直接落地两套池

两层库存减少的是“独立预处理期间占用上游连接”和空闲断连造成的浪费；它不自动减少每个成功请求所需的总 MPC 计算量。当前 [`SidecarWarmer`](../../internal/precompute/sidecar_warmer.go) 的 Interface 只返回已完成握手的 Resource；拆分将同时改变 Go 库存调度、双方 sidecar 的状态转换、附件创建与取消路径。只有阶段 profile 与真实空闲断连数据能证明这次复杂度投入的收益。

重新考虑落地时，验收至少包含：单次请求 PREPARED/READY/online 分阶段 CPU 和墙钟；同容量/参与方的唯一配对与销毁；PREPARED 失败或进程重启后销毁而非复用；不占上游连接的计数证明；固定 CPU 预算下的稳态吞吐、P95、RSS 及上游空闲淘汰损耗。先决定有限 TTL 和总库存内存预算，再决定是否扩大库存。

## TLS 1.2 复用需要重新设计记录计划

[`SelectiveLeaderControl` / `SelectiveFollowerControl`](../../rust/vendor/tlsn-mpc-tls/src/selective.rs)在 required 模式下通过 `used` 永久拒绝第二个请求。客户端 [`WarmClient`](../../rust/vendor/tlsn-mpc-tls/src/record_layer/aead/warm.rs)为 Finished、按容量分片的请求和关闭告警预分配 nonce/CTR，取出时删除记录并烧毁未使用的后缀；当前 [sidecar](../../rust/crates/sidecar-runtime/src/lib.rs)同样约束请求阶段。池层允许 `ReleaseReusable` 并不意味着这些 Adapter 已支持复用。

若后续重做，应给每个请求分配新的认证计划、唯一记录序号及一次性 AES/tag 材料，明确整个连接的总记录/字节预算，并在完整认证和结算前拒绝下一请求。同一 AES-GCM key 下的显式 nonce 必须保持唯一，不能重新从零预热。[RFC 5288 §3](https://www.rfc-editor.org/rfc/rfc5288.html#section-3)规定了这一要求。持久 HTTP/1.1 还要求完整消费上一个响应才能安全复用，不能只看到 SSE DONE 就归还连接；见 [RFC 9112 §9.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-9.3) 与[当前 HTTP Stream](../../internal/response/stream.go)。

## TLS 1.3 的限制来自密钥释放方案

当前凭证前缀用旧代密钥做 MPC，确认投递 KeyUpdate 后向 Hub 释放下一代客户端 traffic secret。后续 KeyUpdate 只从当前 secret 确定性派生；因此 Hub 知道这一代后，也能派生后续客户端各代密钥，不能再依靠同一条派生链向它隐藏下一请求中的新凭证明文。[RFC 8446 §7.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.2)给出了这条派生关系；[本地实现](../../rust/crates/tls13/src/engine.rs)的 `application` 和 `Hub::request` 实现了对应释放顺序。

故当前 canonical HTTP Adapter 每请求都需要秘密 Authorization 的情况下，继续新握手、新会话。普通 TLS 1.3 可以承载多个 HTTP 请求；这里不采纳的是“原封不动地复用本 MPC 密钥释放方案”。若要改动，应首先给出新秘密输入的独立密钥来源和完整生命周期设计，而非删除 `used` 检查。
