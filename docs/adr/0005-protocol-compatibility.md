# ADR 0005：以协议能力管理兼容性，暂不引入版本区间

日期：2026-10-27。状态：已接受。

## 决策

当前只实现 wire/RPC v1，继续精确检查 v1，保留已有必需 feature、角色、TLS 模式和 capacity 检查。不增加内容恒为 `[1,1]` 的版本范围字段，不因对端声明某个范围就接受尚未实现的 v2。滚动升级的兼容单位是经过测试的协议与 MPC 行为集合，不是四个进程的构建版本号。

因此，“四个组件只接受完全一致的构建版本，所以现在必须改为区间协商”不符合当前代码。已有文档中要求同步升级的段落应解释为特定 wire/能力/时序变更的发布约束，不能推广为每次修复都要求四方同版本。

## 当前实际检查的内容

| 层次 | 当前检查 | 不检查的内容 |
| --- | --- | --- |
| Go ↔ Rust sidecar RPC | 二进制 THV1/version=1；hello 的 `protocol_version=1`；角色；能力中所选引擎对应的 TLS、cipher、必需 features；精确资源预算 | Go 或 Rust 构建 SHA、应用发布版本号 |
| Hub ↔ Provider sidecar 配对 | 模式一致、精确 capacity 一致、双方均满足所选引擎的必需 features，并选共同受支持 cipher | 不要求未知的可选 feature 列表逐字相同 |
| Hub ↔ Agent 控制通道 | mTLS/SPIFFE 身份、控制 hello 的 protocol version 1、严格帧/字段、计数器和 generation | Agent 与 Hub 的应用构建版本号 |
| Hub ↔ Agent 数据通道 | mTLS 身份后精确读取 `THD1 || uint16_be(slot)`，槽位及 generation 约束 | 没有 data-channel 版本集合或协商应答 |
| TLS 1.2 sidecar 内部 MPC | TLSNotary commitment 发送并严格比较 crate 的 semver，另检查 MPC 资源配置 | 这个 semver 不是四个 TokenHive 进程的构建号，也不能独自证明本地 fork 电路/时序兼容 |
| TLS 1.3 sidecar 内部 MPC | 所选引擎及公开 policy 配对，按固定协议控制消息执行 | 没有独立的任意版本区间协商 |

上述依据分别见 [Go RPC 与校验](../../internal/sidecar/rpc.go)、[Go 能力配对](../../internal/sidecar/capabilities.go)、[Rust 能力校验](../../rust/crates/sidecar-protocol/src/lib.rs)、[Rust RPC](../../rust/crates/sidecar-protocol/src/rpc.rs)、[Agent 控制](../../internal/agent/control.go)、[数据 hello](../../internal/providerconn/data_hello.go)、[TLSNotary commitment 校验](../../rust/vendor/tlsn/src/verifier.rs)及[TLS 1.3 控制与 policy](../../rust/crates/tls13/src/engine.rs)。

## 可选能力与必需行为不能混淆

在现有 `features` 字符串列表中增加真正可忽略的可选能力，可以保留 v1：接收端只检查自己所需的 features，不因列表中出现额外未知名称而拒绝。但是不得把会改变双方电路、随机材料分配、输出认证、执行轮次或密钥释放顺序的变更伪装成可选能力，然后与旧 peer 混用。

例如 TLS 1.2 的 `precomputed-client-aes` 不只是性能标签，它代表双方执行时序和 nonce 绑定计划；缺失时仍必须在创建/使用会话前拒绝。TLS 1.3 的 `tls13-keyupdate` 和 `authenticated-mpc-output` 同样不能在区间相交时被省略。Exact capacity、TLS 模式、角色、MPC 输出认证和上游投递 ACK 的要求继续独立于 RPC 版本。

相同 semver 或 feature 名也不是任意 fork 的安全兼容证明。修改 MPC 行为时，需要明确新的兼容标识、配对测试及不兼容拒绝条件，不能只比较应用版本的大小关系。

## 为什么直接加范围字段会破坏旧版

当前 Go 使用严格 JSON 解码，Rust hello 与 Capabilities 使用 `deny_unknown_fields`。在 v1 hello/ack 中直接添加 `min_protocol_version`、`max_protocol_version` 或 `supported_versions`，即使语义上是“可选”，旧实现仍会因未知字段拒绝。能力协商本身又先运行在 v1 二进制帧之上；尚未读懂 bootstrap 的对端不能借助后续 JSON 范围修复 framing 不兼容。[Rust RPC 已有拒绝未知 hello 字段的测试](../../rust/crates/sidecar-protocol/src/rpc.rs)。

因此现在增加范围既没有第二个真实实现可选，还会扩大升级表面。不能将“范围相交”作为允许不同密钥释放方案、不同电路时序、不同资源承诺或不受支持 frame version 的理由。

## 当前滚动升级办法

保持兼容 v1 的 bugfix 可以按 Adapter 分批升级，前提是两端配对测试通过、JSON 形状与必需时序没有变化。升级前通过控制通道停止接收新任务，保留正在执行的 lease；等待任务完成后再重启涉及该 Provider 的 sidecar/Agent。一次性材料不跨进程迁移。恢复时重新完成 mTLS、角色/能力校验和预热后再开放 admission；现有 generation 保护旧连接退出时不误清新连接。

某次变更若新增必需能力，应先部署能够理解并保留旧行为的接收方，或使用并行 sidecar socket/独立 route 实现两套兼容组；完成配对验证后再切换发送方和接单策略。若旧新行为没有共同且已验证的组合，就按 Provider 排空并成组升级。不能承诺未经混合版本测试的无中断升级。

## 何时真正实现多版本协商

只有 v2 的 framing、操作、状态机与 Adapter 已真实实现并需要与 v1 并存，才设计版本选择。届时必须明确：

1. bootstrap 使用旧端能读懂的固定格式或并行 listener；不能先发送旧端会拒绝的新字段。
2. 在双方明确知道扩展能力后才交换版本集合，选择双方实际实现的版本；选择结果在创建会话及分配秘密材料之前确认。
3. 版本切换的帧边界、降级政策和选择失败的关闭语义固定；没有交集或缺少必需 feature 时关闭，不回退为普通 TLS。
4. 若改 `THD1`，明确新 magic、长度、槽位含义和升级次序；旧端读不到应答的单向 hello 不能凭空变成可交互范围协议。
5. Agent 控制协议、数据协议、sidecar RPC 和 MPC 行为标识分别演进，避免用一个宽泛应用版本范围掩盖它们之间的约束。

## 验收矩阵

兼容 v1 的每次发布至少验证新 Go/旧 sidecar、旧 Go/新 sidecar、新 Hub/旧 Agent、旧 Hub/新 Agent，以及新旧双方 sidecar 的正反配对。允许的组合须完成真实 MPC 请求、投递 ACK、JSON/SSE 和结算恢复；不允许的组合须在产生上游业务请求之前明确失败。

单独保留以下负面用例：错误角色、未知 frame version、错误 Agent/data magic、未知 JSON 字段、TLS 模式混用、capacity 不一致、缺少任一必需 feature、错误输出认证/投递 ACK。另保留额外未知可选 feature 不影响相同 v1 能力配对的正面用例。未来有 v2 后，再增加无交集、选择未实现版本、切换前后错误帧、篡改选择结果及拒绝降级的测试。

本决策完成了版本区间方案的评估，当前不引入范围协商代码；后续需解决的是具体不兼容变更的混合部署验收，而不是把严格的 v1 检查改为未经实现支持的宽松版本比较。
