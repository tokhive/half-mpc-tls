# ADR 0004：真实上游兼容性与 ClientHello 指纹验收

日期：2026-10-27。状态：验证方法已接受；实际上游准入取决于对应部署的实测。

## 决策

保留受限 TLS 1.3 配置及按 route 显式选择版本、拒绝自动降级。原评审提出的默认改用 TLS 1.3，需要在目标 Provider 出口和目标上游通过兼容性验收后才成立。用可重现的实际 ClientHello 和无凭证请求先验证公共网络路径；不把 OpenSSL 的握手成功等同于本项目引擎兼容，也不把指纹不同等同于已被风控封禁。

## 主来源与本地事实

[RFC 8446 §4.6.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.6.3)允许 Finished 后发送 KeyUpdate，要求使用旧密钥加密更新消息、其后用新密钥发送，并按更新标志处理对向更新。本项目[握手与请求引擎](../../rust/crates/tls13/src/engine.rs)使用 `update_not_requested`，把凭证前缀与后续 HTTP 头/正文分在两个密钥代；这是协议上可表达的行为，目标网关实际是否接受必须测量。

[`wire::client_hello`](../../rust/crates/tls13/src/wire.rs)当前只提供 P-256、`TLS_AES_128_GCM_SHA256` 和 HTTP/1.1。可从公开字段独立提取 cipher、extension 顺序、supported groups、signature algorithms 和 ALPN，无需 API key 或 traffic secret。[FoxIO 的 JA4 定义](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)是指纹算法的主来源；算法只对 ClientHello 特征作归纳，不定义任何目标平台的风控策略。

## 分层验证

| 层次 | 无真实凭证可做的测试 | 能证明与不能证明的内容 |
| --- | --- | --- |
| ClientHello | 生成/捕获本项目实际握手字节，解析与重复比对 JA4 原始组成及哈希 | 证明指纹可重现；不能证明上游是否使用它限流 |
| 公网 TLS | 从实际 Provider 出口连接精确 host/SNI/port，校验证书、版本、cipher、ALPN | 证明该时刻该出口能握手；不保证不同 CDN 节点、其他出口或后续时间 |
| 跨 KeyUpdate 的 HTTP | 对目标公开路径发无 Authorization 的无副作用 GET/HEAD，HTTP 头跨 KeyUpdate；与同一请求不更新密钥的对照比较 | 认证的 401/403 等非 2xx 也有价值，但不能证明付费调用、真实凭证、模型或完整 usage 链路 |
| 本地真实 MPC | 本项目真实双方引擎对独立 TLS 服务端，覆盖 KeyUpdate 前后记录篡改、错误 SNI、请求碎片、服务端更新、完整 HTTP 重组 | 证明本地协议/实现组合；不能替代目标公网互操作 |
| 部署准入 | 受控小额真实调用，分别完成 JSON/SSE、模型与 usage 校验、断连结算 | 需要部署方真实凭证、预算与目标 Provider；不得由前四层结果推断通过 |

公网无凭证探测不调用模型推理，不读取用户环境中的 API key，不发送真实 Authorization，不关闭证书或 DNS 验证。认证失败响应可能在请求完整处理前就产生；因此探测需记录是否提前收到响应，并把这种情况标为“不能确认跨代请求被完整消费”，而不是自动判定通过。本地独立服务端应直接检查重组后的完整 HTTP 字节以排除这一歧义。[已有本地原型](../../experiments/tls13-keyupdate/probe.py)完成后一种检查，但使用普通 TLS 握手，不能替代真实 MPC 或本项目 ClientHello 验证。

## 结果记录与故障解释

每条结果记录时间、出口/运行地点、host/SNI/port、TLS/cipher/ALPN、握手与请求阶段、请求方式、HTTP 状态、是否提前响应、是否收到 TLS alert/超时，以及构建产物摘要。只保留脱敏摘要，不记录真实凭证、traffic secret 或业务请求正文。失败须区分 DNS/TCP、证书、协议协商、TLS KeyUpdate、HTTP 拒绝与业务鉴权；WAF challenge 或 403 本身不是 KeyUpdate 不兼容的充分证据。

指纹验收应至少对重复握手及双方构建进行字节层解析；变更 cipher/extension 不能只为模仿浏览器而声明本引擎未实现的能力。对目标风控的效果只能通过目标授权环境中的对照结果说明，不能承诺“保留 Provider IP 就不会封号”。

本 ADR 记录方法和准入条件，不声称已完成任何公网或带真实凭证验收；实际执行结果应写入独立性能/兼容性报告，并按目标 route 标注通过范围。
