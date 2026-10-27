# ADR 0003：保持每会话独占 Provider 数据连接

日期：2026-10-27。状态：已接受。

## 决策

当前继续使用 Provider 主动发起的 mTLS TCP 数据连接，按会话独占一个连接 generation。暂不为降低 socket 数量改用单 TCP 连接复用全部会话，也不立即迁移到 QUIC。将 Provider 的数据槽位视为预热中、READY 和在线会话共同占用的有限资源，按实际并发预算配置。

## 证据与取舍

[`Registry::ReserveProvider`](../../internal/providerconn/registry.go)为一个会话选择未保留的物理槽位，其后所有 RPC、MPC 附件和本地桥接都绑定该槽位和 generation；释放会关闭这一代连接。旧会话不能迁移到新连接，旧 generation 的清理也不能释放新会话。此行为既是资源隔离，也是取消和恢复的一部分。

[隧道读取循环](../../internal/tunnel/client.go)通过一个物理连接逐帧分配逻辑流。逻辑流的接收队列有界，不能被调用方及时消费时会形成背压；同一 TCP 连接上的其他帧也可能等待。[隔离回归](../../internal/providerconn/isolation_test.go)刻意阻塞一个后台会话，确认另一个物理槽位中的在线会话仍可发送并收到响应。因此恢复为全局共用一个 TCP 连接会撤销已有、可验证的隔离保证。

代价是文件描述符、mTLS 重连及会话槽位消耗。默认 32 个槽位是一个 Provider 的所有容量/凭证库存的合计预算，并非只允许 32 个在线请求的独立限制。容量规划至少核对：

```text
可用槽位需求 = 活跃请求会话 + READY 库存 + 正在预热的会话
```

还需为重连补充留出余量；公式不是硬性无限扩容规则。全局预热并发约束 CPU 工作数量，Provider 槽位约束传输资源，两者不能互相替代。[容量说明](../performance-design-zh.md)和[槽位常量](../../internal/providerconn/data_hello.go)是当前配置依据。

## 为什么现在不替换为 QUIC

QUIC 提供分别流控的流，且可减少跨流的丢包队首阻塞；但同一连接仍共享拥塞和连接级资源。[RFC 9000 §2](https://www.rfc-editor.org/rfc/rfc9000.html#section-2)、[§4](https://www.rfc-editor.org/rfc/rfc9000.html#section-4)、[§13](https://www.rfc-editor.org/rfc/rfc9000.html#section-13)说明了这些机制。传输包 ACK 只证明对端协议栈接收/入队，不能替代本项目的上游 socket 实际写入 ACK。直接用 QUIC ACK 释放 TLS 1.3 新代密钥会改变现有投递屏障的含义。

目前没有目标部署网络下“socket/mTLS 重连成本已超过 MPC 预热成本”的证据。换用 UDP/QUIC 还需要新的证书身份绑定、逐流队列/内存预算、取消/半关闭语义、断网恢复和逐步升级策略；仅换传输库不能证明业务隔离与结算恢复正确。

## 重新考虑的条件与验收

只有跨机 profile 证明现有数据连接数、重连 CPU 或丢包队首阻塞构成实际瓶颈，才开始 QUIC 对照实现。对照必须保持相同 MPC 引擎、资源预算、请求量及 Provider 身份策略；同时测量首内容 P95/P99、吞吐、FD/RSS、重连成本、单流拥塞对其他会话影响，并保留 Provider 到上游的累计字节/hash 投递确认。

通过阻塞后台流、终止单流、连接整体中断、旧 generation 延迟清理、恶意超量开流和丢包网络测试后，才允许替换当前 Adapter。现阶段先使用已有槽位上限与统计进行容量管理。
