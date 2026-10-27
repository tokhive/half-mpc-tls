# 性能调整与验证记录

更新：2026-10-24。目标同时覆盖请求首字节延迟、大 prompt、持续吞吐和资源成本。

## 已实现的生产路径调整

### 1. 有界流水传输

普通 `tunnel.Client.Open` 保留写入完成即远端 socket 交付完成的语义。
新增 `OpenBuffered` 用于 sidecar RPC 和 MPC：每条逻辑流最多允许 8 个未确认帧、
512 KiB 未确认字节，窗口满时等待累计交付 ACK。每个 ACK 仍匹配字节计数和
SHA-256 前缀；错误 ACK 使隧道失败。`FlushDelivery` 提供显式完整交付屏障。

帧头与内容合并为一次写入。发布预期 ACK 时持锁，但网络写入不再持有
`deliveryMu`，避免 ACK 处理和网络写入相互等待。完整请求仍等待 Rust sidecar
报告 Provider 上游 socket 的交付结果；普通 RPC 的返回结果是该操作的完成屏障。
交付 ACK 表示 socket 写入完成，不代表上游应用已处理请求。

### 2. Provider 本地桥接

分机部署中，Hub 通过保留的 `provider-bridge.tokenhive.internal:1` 控制端点
提交 session ID、精确 capacity、attachment token 和目标地址。Provider 本地
打开对应 sidecar 上游附件以及允许的上游 TCP socket，执行原有交付确认桥接。
TLS 字节不再沿 Provider sidecar → Hub → Provider Agent 的路径绕行。

控制请求以 4 字节大端长度开头，JSON 上限 4096 字节，版本为 1；拒绝未知字段、
错误版本、无效会话、未支持 capacity、非法 token 和未允许出口。单字节 1 表示
两个本地端点已建立，0 表示失败。成功后的连接只作为生命周期句柄，关闭或后续
任何输入都会终止桥接；桥接失败会关闭句柄，使 Hub 将会话淘汰。

内部逻辑端口与真实上游出口白名单分开检查，增加内部端口不会授权真实域名的新端口。
该功能要求 Hub 与 Provider Agent 同步升级；旧 Agent 会拒绝新控制端点而不是回退。

### 3. 路由和容量

路由优先选择有 READY 会话的候选；随后比较从请求开始交付到认证 HTTP 响应头的
EWMA 延迟（并非精确首 token 指标），未观测候选使用 1 秒初值。冷候选另计平均
预热耗时和失败退避。延迟相同时优先较小容量，再比较在途 lease 数量，最后保留
任务哈希打散。同一请求不会因选择失败而重复派发；库存快照存在并发竞争，实际
Acquire 仍可能等待。

两端支持以下完全相同的容量承诺，每个进程只声明一个档位：

| 参数 | 请求明文上限 | 客户端记录预算 |
|---|---:|---:|
| `baseline` | 4 KiB | 4 |
| `16k` | 16 KiB | 4 |
| `64k` | 64 KiB | 7 |
| `256k` | 256 KiB | 19 |
| `1m` | 1 MiB | 67 |
| `5m` | 5 MiB | 323 |

各档响应上限仍为 16 MiB，在线响应记录预算仍为 6。
`testdata/mpc-capacities.json` 由 Go/Rust 两端测试读取，记录预算不匹配也必须拒绝。

Hub 新增 `hub_sidecar_sockets`，Provider 新增 `sidecar_sockets`，均为档位名到
本地 Unix socket 路径的映射。单 socket 配置继续有效，最终必须通过精确 capacity
协商。每个已配置 socket 应运行同名 `--capacity` 的独立 sidecar 进程，例如：

```json
{
  "hub_sidecar_sockets": {
    "baseline": "/run/tokenhive/hub-4k.sock",
    "64k": "/run/tokenhive/hub-64k.sock"
  }
}
```

Provider 同样配置 `sidecar_sockets`，其保留逻辑端口 1..6 按上述表顺序映射。
配置多个 route，分别使用这些 capacity，即可在同一 Hub 上选择对应预热库存。
不应把所有请求都分配到最大档位：MPC 预处理工作量仍与容量预算有关。

### 4. 长流响应的库存余量

autoscaler 将当前活动 lease 数量计入会话总上限，额外部分受 `MaxLeased` 约束。
默认上限是 `targetReady + SessionHeadroom + min(leased, MaxLeased)`；这不是无限
扩容，也不是独立的请求并发限制。下线时仍将目标和总上限设为零，但允许在途结束。

Hub 可配置 `warm_concurrency`（每 pool key）、`max_ready`、`max_leased`（默认 64）。
`target_ready` 现在也正确作为 autoscaler 的最低库存生效。选择更高并发前，应测量
每档每会话峰值内存和总后台 CPU；多 key 的预热并发会叠加。

### 5. 会话独占传输与全局预热限额

Provider Agent 新增 `data_tunnels`，默认 32，允许 1..256；每条连接仍由 Provider
发起，并经过同样的 mTLS 1.3 证书及 SPIFFE 身份认证。认证后先发送 6 字节
`THD1 || uint16_be(slot)`，槽位范围 0..255。版本、槽位或 Provider 身份不合法就
关闭连接；握手和 hello 合计限制 10 秒。**Hub 与 Provider Agent 必须同步升级**，
旧版不发送该 hello，不能与新版混用；sidecar RPC 协议不变。

每次预热先独占一个空闲槽位；该会话的 RPC、MPC 附件和桥接控制流都绑定到
同一物理连接及其 generation，直到失败、淘汰或请求结束。后台会话与在线会话
因此没有共同的 TCP 接收队列或写锁。槽位耗尽立即返回不可用，由池退避，不能
借用已占用连接。独占连接先关闭，再清理逻辑流，避免拥塞流阻塞会话回收。
每个连接 generation 只服务一个会话，释放后由 Agent 重连补充；旧 generation
的清理既不能删除新连接，也不能让旧会话迁移到新连接。

32 条连接是每 Provider 的预热中、READY 和在途会话总预算；跨容量和 credential
的库存共享这个预算。应按这些库存的合计配置 `data_tunnels`，并为补库存留出余量。
传输隔离不等于独占物理带宽或 CPU，同一会话内的逻辑流仍复用该连接。

Hub 新增 `global_warm_concurrency`，默认 2，限制所有 pool key 合计的昂贵预热
任务；原有 `warm_concurrency` 继续限制单 key。等待全局许可计入 Warming 库存，
但不消耗单次 `warm_timeout`；拿到许可后再次检查是否仍需要库存。取消、下线、
缩容和关闭不会让排队任务永久占住许可。此限制约束同时执行的任务数，不能替代
各 capacity 的单会话内存测量。

## TLS 1.3 KeyUpdate 早期原型

`experiments/tls13-keyupdate/probe.py` 使用本地、临时证书和虚构 API key。
它建立经过证书和 hostname 验证的 TLS 1.3 连接，在旧客户端密钥下发送认证头，
随后发送 `KeyUpdate(update_not_requested)`，并用独立本地 AES-GCM 在新密钥下
生成剩余 HTTP 头与正文。原生 OpenSSL 服务端重组完整请求并返回 HTTP 响应。

```sh
python3 experiments/tls13-keyupdate/probe.py
```

依赖 Python 3、`cryptography` 和 `openssl` 命令。只在临时目录生成测试流量秘密，
读入后删除，不输出秘密；它模拟下一代客户端密钥交给 Hub 的效果，**没有执行 MPC**。

依据 [RFC 8446 §4.6.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.6.3)、
[§7.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.2)，这个设计有机会把
请求方向 MPC 的数据加密范围缩到固定认证片段、KeyUpdate 和密钥派生。
与预先计算整个请求容量的 AES 密钥流相比，它有机会同时降低在线和总计算成本。

本机结果：4 KiB、64 KiB、1 MiB、5 MiB 的正文都完成请求／响应；新密钥不能认证
旧认证记录，旧密钥不能认证新正文，篡改密文也被拒绝。测试实际协商
`TLS_AES_256_GCM_SHA384`。Python 生成新阶段正文记录分别约 0.037、0.177、2.352、
11.595 ms，只包含本地加密，不包含握手、MPC、网络、上游推理，不能作为生产 SLO。

## 后续协议迁移边界

该 Python 原型仅保留作独立互操作实验。现在已实现 Rust TLS 1.3 MPC 握手、
HKDF、旧阶段认证记录、KeyUpdate 和带输出认证的新代密钥释放，并接入 sidecar
及 Go 路由。两端显式启用 `--tls-version 1.3`，route 设置 `tls_version: "1.3"`，
不允许自动降级；配置见 [接入指南](business-integration-zh.md)。
真实目标上游仍需单独验证，局部 AEAD 测试不构成协议安全证明。

迁移仍要求旧客户端 traffic secret 永不释放给 Hub，新阶段密钥永不释放给
Provider；Hub 只能在认证握手及正确切换计划成立后获得新密钥。后续阶段不再具备
每个请求字节都由 Provider 联合授权的属性，需要明确维持半诚实 Hub 的信任边界。
新密钥阶段不能再次发送要对 Hub 隐藏的 credential；首版继续一次请求一个会话。

### 已完成：TLS 1.2 客户端 AES 预求值

已获专项授权并实现。两端在握手中绑定客户端每条记录的显式 nonce 与 CTR，
随后随共享会话密钥的 PRF 求值执行全部已配置客户端 AES 块和 J0 标签掩码。
会话成为 READY 之前这部分计算已完成。服务端记录的 nonce 仍由上游确定，
不套用这套客户端计划。

预留顺序是序号 0 的 16 字节 Finished、按 16 KiB 分片的请求容量、以及关闭
告警的余量。实际请求可以小于容量；每次取出从 CTR=2 开始的前缀，未用完的
记录后缀被丢弃，不能转给后续记录或其他会话。首个短应用记录之后不再允许
应用记录，告警之后不再允许写入。双方的规范请求计划还检查准确的末片长度，
并永久拒绝第二个请求。错误 nonce、重复消费、越界、错误阶段和耗尽均失败，
不回退到临时重用材料。

凭证记录的 AES 输出始终留在 VM 中，在线阶段仍以双方各自输入构造混合明文，
只解码密文。只有经双方规范模板验证的公共记录才解码其密钥流。客户端密钥不
释放；J0 只以加法份额供现有 GHASH 路径使用。在线仍有输入提交、线性电路、
输出解码、GHASH 与通信，因此不是“零 MPC”或消除了随容量增长的总成本。

新增必需能力 `precomputed-client-aes`，Go 单端校验、双端协商和 Rust 校验均检查。
**Hub、Provider Agent 及两端 sidecar 必须同步升级**；新旧求值时序不能混用。
旧通用 TLSNotary 非 selective 模式保留原来的动态记录路径。

验证包括：理想 VM 中应用输入尚未提交时，已绑定的 AES 求值完成；16 字节块边界、
16 KiB 记录边界、短尾和提前关闭的密文／标签逐条对照独立 AES-GCM；伪造 Provider
公共字节不能替换 Hub 模板；密文篡改、错误 AAD 序号、nonce 重放、错误标签计划、
材料耗尽和请求重入均被拒绝。真实两方 MPC 的握手、请求、上游交付及认证响应
另行执行，不以理想 VM 测试代替真实协议验证。这些测试不构成形式化安全证明。

TLS 1.3 路径把 MPC 凭证前缀限制为固定 1 KiB，正文不再按容量预求值 AES。
真实两方容量矩阵、样本计时和安全边界见 [引擎说明](../rust/crates/tls13/README.md)。
四进程业务验证另见 [验收记录](integration-validation.md)。

## 性能验证

可复现的传输基准：

```sh
go test ./internal/tunnel -run '^$' -bench BenchmarkDeliveryPipeline -benchtime=1x -count=3
```

在 AMD EPYC 7R32 上，模拟每次交付 ACK 延迟 10 ms，连续发送 32 个 1 KiB 数据块，
两种模式都等待最后交付确认：逐次确认耗时 325–326 ms，8 帧窗口耗时 40.9–41.2 ms，
约减少 87% 的等待时间。这是隔离传输层的人工延迟实验，不是端到端 API 提速倍率。

部署测试仍需覆盖不同 RTT／带宽／丢包、冷暖池、短请求／长 prompt、持续并发和
慢 Consumer，记录 p50/p95/p99、预热速度、失败率、MPC 字节、CPU、峰值内存。

本次传输隔离的回归覆盖：一条连接填满接收队列并阻塞时，另一条连接仍能完成
写入、交付 ACK 和响应读取；旧 generation 释放不影响重连；真实本地 mTLS
监听器接受同一 Provider 的多个槽位并拒绝非法 hello／未列入白名单的身份；
跨 key 预热并发受总限额控制，等待者能随关闭退出。没有新增公网端到端延迟结论。

AES 前移后的真实 MPC 同机样本：4 KiB 容量下，3,358 字节规范请求在线交付为
29、29、31 ms（此前单次对照 93 ms）；预热握手为 1,187–1,214 ms。17,695 字节
跨两条 TLS 记录的请求也通过，在线交付 158 ms。样本范围及 64 KiB 对照进程
被 SIGKILL 终止的限制见 `benchmark-results.md`；不据此宣称大容量部署验证完成。

本轮最终检查通过：`go test -race ./...`、`go vet ./...`、Go/Rust 进程集成测试、
`cargo test --workspace`、变更后 selective 计划专项测试、Clippy（warnings 视为错误）
及 rustfmt。另以 release 模式显式运行默认忽略的真实 MPC 请求测试（短请求与跨记录
请求），以及开启 AES 预求值的两项密钥释放测试：正确身份完成认证后释放，错误 DNS
身份拒绝释放。所有这些显式测试通过；前述 64 KiB 对照中止仍单独保留，不能算通过。


## 2026-10-24：真实四进程压测

新增公开 Go SDK → Go Hub → 两端 Rust sidecar / Provider Agent → 合成 HTTPS 上游的持续压测，覆盖固定并发、固定到达速率、JSON/SSE、1 MiB/5 MiB prompt、数据通道双向各 5 ms 延迟、CPU/RSS 和回执核对。发现并修复空预热池等待者互相唤醒导致的 CPU 空转。

本机 2 CPU 条件下，修复后小请求稳态约 1.37 请求/秒；1 RPS 到达的 JSON P95 约 278 ms（含上游固定 200 ms），过载时仍有秒级长尾和超时。详细方法、全部错误、前后对照和原始数据见 [压测报告](performance/e2e-2026-10-24.md)。早期独立引擎微基准不等于这些业务端到端指标。

## 2026-10-26：公平、有界会话队列

会话获取改为每个 pool key 独立的 FIFO 队列，后到请求不能抢占较早等待者的 ready 库存。补库存只通知队首；队首取得会话或取消后再通知下一位。调用方取消、排队超时、注销、父 context 取消及关闭都会移除等待者；注销再注册同一个 key 不会把旧等待者迁移到新一代会话池。

Hub 支持 `max_waiters`（默认 64）和 `queue_wait_timeout_ms`（默认 10000），对应公开 Go 字段 `MaxWaiters`、`QueueWaitTimeoutMS`。限制只作用于等会话，不截断已经取得会话的长响应；总请求 deadline 仍有效。队列满或排队超时分别返回 HTTP 503 `queue_full` / `queue_timeout`，SDK 可读取错误码和 `Retry-After`。失败任务的幂等键及余额预留规则见业务接入文档。

同时修复预热线程在检查库存与订阅通知之间可能丢失唤醒的问题：现在二者在同一临界区完成，避免等待下一次健康检查才开始补库存。路由与 readiness 只将扣除排队需求后的库存视为立即可用。该修改不增加 MPC 预处理的 CPU 吞吐上限，也不承诺跨 pool key 的全局公平性。

完整复测与过载拒绝、回执核对结果见 [2026-10-26 性能报告](performance/e2e-2026-10-26.md)。
