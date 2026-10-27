# ADR 0007：复用单会话 HMAC 前缀压缩状态

日期：2026-10-27。状态：已实现；以向量、独立 TLS fixture 和四进程验证为准，不构成密码协议形式化审计。

## 依据与决定

分阶段 profile 显示，TLS 1.3 的主要准备成本位于握手和应用密钥计划，ECDHE 份额阶段相对较小；原生栈中可见大量 garbling、序列化和 AES 工作。因此先减少密钥计划重复求值，不先增加库存或改写传输协议。

对同一 VM 中同一 32 字节 HMAC key，先计算一次 SHA-256 的 `(K XOR ipad)` 和 `(K XOR opad)` 首块状态，后续不同 label/context 从该状态分叉并产生新输出。[RFC 2104 §4](https://www.rfc-editor.org/rfc/rfc2104.html#section-4)明确允许缓存这两个压缩状态，并要求将它们按秘密密钥保护。

实现见 [KeyedHmac](../../rust/crates/tls13/src/schedule.rs)：只保留当前 VM 的秘密 state 引用和 processed 计数，不输出状态明文，不做跨会话、跨进程缓存。`Sha256::clone` 复制状态引用与缓冲描述，`compress/finalize` 对每个消息创建新的输出；缓存基态不被修改。这不同于复用 OT、nonce、garbling 随机材料或已消费记录。

当前固定计划中，handshake secret 供三个 HKDF label、master secret 供两个 application label、旧 client secret 供 traffic update/key/IV。该固定 SHA-256 HMAC 计划的压缩块由 40 个降至 30 个；不表示整个握手 CPU 或端到端延迟必然减少 25%，因为还有 ECDHE、OT、AES、传输、排队与上游等待。

## 协议兼容约束

双方 VM 引用分配与执行计划改变，必须成对使用新 sidecar。Go/Rust capabilities 对 TLS 1.3 增加必需能力 `tls13-keyed-hmac-state`，不把它当作可忽略的遥测 feature。

MPC 控制层另使用 schedule revision 2 和追加到旧变体范围之外的 `InitV2`（Bincode 索引 7）。旧 `Init` 索引 0 保留仅用于明确拒绝。不能只给原 Init 尾部加字段：Bincode 1 的默认反序列化允许尾部字节，旧 peer 可能忽略追加字段。真实 `Io::from_io` duplex 测试验证旧 decoder 拒绝新变体、新实现拒绝旧 Init；检查在贡献凭证或发送 TLS ClientHello 之前完成。

这没有引入 RPC/frame v2，外层仍为 v1；RPC 兼容和 MPC 时序兼容分别判断。旧 Go 即使忽略未知 feature，内部 InitV2 仍阻止新旧 sidecar 混用。升级需要排空相关 Provider 并更新双方 sidecar 和能力校验方，不能只重启其中一端后继续使用旧库存。

## 验证要求

- 独立 HMAC 对照覆盖空消息、不同片段、SHA-256 填充边界、多个块以及重复消息，检查缓存状态不受先前消息污染。
- RFC 8448 / 本地 HKDF 对照、输出 MAC 伪造拒绝及密钥代/记录认证测试继续通过。
- 真实独立 rustls 服务端覆盖六档请求、KeyUpdate、错误 DNS、计划不一致和非法凭证字符。
- 四进程 JSON/SSE/SDK、持久结算、故障恢复及持续负载按最终二进制验证。
- 同机优化前后使用相同负载、采样、配置和构建参数，记录不同二进制 SHA；分阶段嵌套 CPU 不相加，单轮观察不外推为统计显著或跨硬件提速。
