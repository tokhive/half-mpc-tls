# TokenHive TLS 1.2 Selective MPC 实现设计

性能调整的实现、容量档位与验证结果见 [performance-design-zh.md](performance-design-zh.md)。
生产路径仍为 TLS 1.2；TLS 1.3 KeyUpdate 目前是独立的本地兼容性原型。

## 1. 目标和信任模型

本设计用于 TokenHive 的第一版可运行实现，目标是：

1. Provider 的上游 API key 不以明文发送给 Hub，也不进入 Hub 的日志、数据库或进程内存。
2. 上游 TLS 连接由 Provider 的网络发起，上游看到 Provider 的出口 IP。
3. Hub 能验证并解密上游返回的真实 TLS 响应。
4. MPC 只用于客户端请求方向；响应方向使用普通 TLS 1.2 AES-GCM 解密。
5. Consumer 信任 Hub，不要求 Consumer 独立验证响应。

威胁模型：

- Hub 是诚实但好奇的参与方。Hub 按协议调用 MPC，不主动复用 nonce、伪造 block 角色或请求秘密 block 的 keystream。
- Provider 可能恶意，包括伪造响应、篡改密文、重放响应、连接假上游或中途断开连接。
- 上游 API 和其公开信任链可信。
- 不考虑 Hub 与 Provider 串通。

本设计不抵抗主动篡改 Hub 程序或 MPC 输入的恶意 Hub。nonce 和 sequence 的唯一性仍必须由程序状态机强制保证，以防实现错误和并发竞争。

MPC 的安全要求是不对称的：API key 隐私只要求抵抗半诚实 Hub；协议正确性必须抵抗恶意 Provider。Provider 发送无效 MPC 消息、错误份额或不一致状态时，Hub 必须能够检测并中止 session，不能继续结算。

## 2. 组件划分

第一版划分为 **5 个内部组件**，另有 Consumer、上游 API 和数据库三个外部依赖。

```text
Consumer
   |
   v
+----------------------+       +----------------------+        +-------------------+
| 1. Hub API Gateway   |------>| 2. Hub Coordinator   |<======>| 4. Provider Agent |
+----------------------+       +----------+-----------+ control+---------+---------+
                                           |                              |
                                 local RPC |                              | TCP relay
                                           v                              v
                                +----------------------+             Upstream API
                                | 3. Hub MPC-TLS Engine|
                                +----------+-----------+
                                           || encrypted MPC channel
                                           ||
                                +----------v-----------+
                                | 5. Provider MPC      |
                                |    Engine            |
                                +----------+-----------+
                                           ^
                                           | local RPC
                                           +---- Provider Agent
```

### 2.1 Hub API Gateway

职责：

- 向 Consumer 暴露兼容上游格式的 HTTP API。
- 完成 Consumer 身份认证、限流和请求大小限制。
- 将请求交给 Hub Coordinator。
- 将已验证的普通响应或 SSE 流返回 Consumer。
- 不处理 MPC、TLS record 或 Provider API key。

建议实现：Go。

### 2.2 Hub Coordinator

职责：

- Provider 注册、健康检查、模型能力和剩余额度管理。
- Provider 选择、任务调度、超时、重试和结算状态管理。
- 把 Consumer 请求规范化成确定性的 HTTP/1.1 请求字节。
- 管理 MPC-TLS 连接池和每条连接的生命周期。
- 强制每条连接最多一个 in-flight 请求。
- 检查响应的 HTTP 状态、模型字段、usage 和上游 request ID。
- 记录任务、请求哈希、响应哈希和计费事件。

建议实现：Go。首期将调度和结算放在同一服务中，规模扩大后再拆分。

### 2.3 Hub MPC-TLS Engine

职责：

- 作为 TLS 1.2 客户端状态机的 Hub 一侧参与方。
- 与 Provider MPC Engine 联合完成 ECDHE、PRF、Finished 和 key block 派生。
- 保留客户端写密钥份额，不重建完整 `client_write_key`。
- 获得完整 `server_write_key` 和 `server_write_IV`。
- 验证上游证书链、SNI、hostname、握手签名和 Finished。
- 对公开请求 block 输出 keystream，对 API key block 只输出 ciphertext。
- 组装 TLS 1.2 AES-GCM record 和 tag。
- 验证并解密服务端 TLS records，向 Gateway 流式输出 HTTP 数据。
- 持有 TLS sequence、explicit nonce 和 record 边界的权威状态。

建议实现：Rust sidecar，通过 Unix domain socket 或 loopback gRPC 与 Hub Coordinator 通信。

### 2.4 Provider Agent

职责：

- 与 Hub 建立经过双向认证的长期控制通道。
- 根据 Hub 指令，从 Provider 机器发起到允许域名和端口的 TCP 连接。
- 在 Provider MPC Engine 和 Hub MPC-TLS Engine 之间转发 MPC 消息。
- 将最终 TLS record 原样写入指定的上游 socket。
- 将上游返回的 TLS record 原样转发给 Hub。
- 执行基本 egress allowlist、带宽限制、超时和 socket 生命周期管理。
- 不解析 HTTP，不在日志中记录 TLS 明文或 API key。

建议实现：Go。

### 2.5 Provider MPC Engine

职责：

- 从 Provider 本地配置或系统密钥库加载 API key。
- API key 只通过本地 `credential_id` 引用，不通过控制通道发送。
- 参与 TLS 1.2 握手和客户端写密钥的秘密共享。
- 在秘密 block 电路中提供 API key 字节。
- 对公开 block 参与 AES keystream 计算。
- 对 Hub 证明或认证自己的 MPC 执行状态；非法输入或不一致份额只能导致协议中止，不能产生被 Hub 接受的 session。
- 独立维护 session、sequence、nonce 和 block 使用状态，避免意外重复。
- 完成后清除连接级秘密份额和临时 MPC 数据。

建议实现：Rust sidecar。Provider Agent 只能提交 `credential_id`，不能要求该组件导出密钥。

## 3. 外部依赖

### Consumer

只与 Hub API Gateway 通信并信任 Hub 返回的结果，不参与 MPC 或证明验证。

### Upstream API

无需任何协议修改。第一版固定使用：

- TLS 1.2
- HTTP/1.1
- ECDHE
- AES-GCM
- 禁用 TLS session resumption、renegotiation 和 compression

具体 cipher suite 必须由 allowlist 控制，不能接受运行时降级到 CBC 或未实现的算法。

### Durable Store

保存 Provider 元数据、任务状态、账本和审计哈希。不得保存 API key、TLS master secret、客户端写密钥份额或 MPC 中间值。

## 4. 关键接口

### 4.1 Consumer API

第一版只支持一个明确的上游 API 形态，再逐步扩展。Gateway 保留 Consumer 请求格式，但 Coordinator 必须重新序列化，不直接转发 Consumer 提供的原始 headers。

### 4.2 Hub 与 Provider 控制协议

控制通道采用 mTLS gRPC 或已有 WebSocket 通道，至少包含：

```text
RegisterProvider(provider_id, capabilities)
OpenUpstreamConnection(session_id, host, port, sni)
MpcFrame(session_id, payload)
WriteTlsRecords(session_id, record_bytes)
UpstreamTlsRecords(session_id, record_bytes)
CloseSession(session_id, reason)
Heartbeat(provider_id, capacity)
```

所有消息都绑定 `provider_id + session_id + monotonic_message_id`。业务重试必须创建新的 `task_attempt_id`，不能重用已经消费的 TLS record 状态。

### 4.3 Hub 本地密码接口

Go/Rust 本地连接采用 [`sidecar-rpc-v1.md`](sidecar-rpc-v1.md) 定义的有界二进制帧。
连接建立后必须先完成版本和 sidecar role 绑定；每个方向维护从 1 开始、严格递增的
frame sequence。命令 JSON 上限为 64 KiB，大块 canonical request 和 TLS record
必须使用每帧不超过 64 KiB 的 stream frame。任何序号跳跃、截断帧、未知字段、角色
不匹配或超限 payload 都会污染并关闭整个本地连接，其上的 session 不可复用。

```text
CreateSession(session_id, upstream_policy)
RunHandshake(session_id, provider_channel)
EncryptRequest(session_id, task_id, adapter, credential_length, public_request_hash, canonical_request)
FeedServerRecords(session_id, bytes)
CloseSession(session_id)
```

`secret_layout` 由固定模板生成，不能由 Consumer 直接指定。它只描述 API key 在规范化请求中的长度和位置。

### 4.4 Provider 本地密码接口

```text
BindCredential(session_id, credential_id, upstream_policy)
RunHandshake(session_id, hub_channel)
ContributeRequestEncryption(session_id, task_id, public_request_hash)
DestroySession(session_id)
```

接口不提供 `GetCredential`、任意 AES block 加密或任意 nonce 输入能力。

## 5. 单次连接和请求时序

### 5.1 连接预热

1. Coordinator 为 Provider 分配 `session_id`。
2. Provider Agent 从本机建立到上游的 TCP 连接。
3. 两个 MPC-TLS Engine 联合执行 TLS 1.2 握手。
4. Hub 验证证书、hostname、握手签名和 server Finished。
5. Hub 获得完整服务端写密钥；客户端写密钥保持双方秘密共享。
6. 连接进入 `READY`，放入对应 Provider 和模型的连接池。

当前实现已在 `internal/precompute` 增加业务级预热池。池单元不是可复制的通用
OT/garbled material，而是完成了 MPC preprocessing、上游 TLS 1.2 握手并保留所有
sequence、key share 和 response task 的完整 live session。池按 Provider、本地
`credential_id`、上游 host/port/SNI 和精确 MPC capacity 隔离，后台维持目标
`READY` 数量；预热失败指数退避，超时、空闲过期、寿命到期或健康检查失败都会销毁
session 并补货。预计算状态只保存在内存中，不序列化、不持久化，也不跨 session
复用。

每个池 key 可通过 `RegisterWithLimits` 和 `SetTarget` 独立调整 `targetReady` 与
`maxSessions`。缩容只立即关闭空闲 session，不打断正在处理请求的 lease；缩到零后，
在途 lease 完成归还时销毁且不再补货。`Stats` 提供 ready/leased/warming、命中/未命中、
累计等待与预热耗时、连续/累计失败，以及健康、空闲、寿命和缩容淘汰计数，供部署层
接入现有监控系统。

`precompute.Autoscaler` 可进一步自动调整库存。其目标公式为
`QPS × 成功预热平均耗时 × 安全系数`，并限制在配置的最小/最大范围内；出现 pool miss
立即扩容，只有连续多个低负载采样窗口才逐步缩容。Provider 下线事件会立即把目标降到
零但保留在途 lease。控制器同时输出所需与已配置的 warm concurrency 及 saturation
状态，因为当长期请求速率超过 MPC 预处理吞吐时，单纯增加空闲库存只能延迟耗尽，不能
解决容量不足。

`internal/agent` 已将 Provider 在线状态接入 autoscaler。Provider 主动建立强制双向
TLS 1.3 控制连接，其 `provider_id` 必须匹配已验证客户端证书中的
`spiffe://<trust-domain>/provider/<provider-id>` URI SAN，不能仅信任 JSON 自报身份。
严格、有界的 heartbeat 包含单调 counter 和 `accepting` 状态；主动 drain、断线、超时、
重放、乱序或畸形消息都会把对应 key 的库存降到零，但不打断在途 lease。Provider 对
网络错误和短暂 duplicate instance 使用有界指数退避重连，认证或协议错误则停止重试。
这里的 mTLS 1.3 仅保护 Agent 控制面，上游模型连接仍严格使用独立的 MPC TLS 1.2。

`precompute.SidecarWarmer` 已接通两端 role-fixed sidecar、MPC attachment、Provider
网络 `UpstreamOpener`、delivery ACK relay 和 Hub authenticated response stream。
默认 `ConservativeConfig` 将每条预热 session 限制为一次 lease 使用，完成或失败后均
销毁并异步补充，避免错误假设剩余 MPC 容量可安全复用。concrete warmer 接受六种精确
capacity：4 KiB、16 KiB、64 KiB、256 KiB、1 MiB、5 MiB；协商结果必须与 pool key 和 route 完全一致，不能混用。

若 Hub 与 Provider Agent 分机部署，池本身保持不变，由经过认证的 Provider Agent
控制面实现同一个 `Warmer` 接口；`UpstreamOpener` 必须继续从 Provider 网络发起并执行
既有 egress policy，禁止退化为 Hub 直接拨号。

### 5.2 请求

1. Gateway 接收 Consumer 请求。
2. Coordinator 选择 Provider 和一条 `READY` 连接。
3. Coordinator 删除 Consumer 自带的 Authorization、Host、Content-Length 等敏感或可冲突 headers。
4. Coordinator 生成唯一的 canonical HTTP/1.1 请求和 `request_hash`。
5. Provider MPC Engine 根据 `credential_id` 提供 API key 私有输入。
6. 两侧 MPC Engine 对包含 API key 的 record 执行 selective encryption；不包含秘密区间的
   后续 body record 校验 canonical 模板后走 public keystream 快速路径。
7. Hub MPC-TLS Engine 生成完整 TLS record，递增客户端 sequence。
8. Provider Agent 将 record 原样写入上游 socket。
9. Provider Agent 仅在完整 socket 写入返回后，按累计字节数和 SHA-256 前缀向本地
   sidecar 返回 delivery ACK；Provider sidecar 的请求操作在全部密文字节被确认前不返回。

### 5.3 响应

1. Provider Agent 将服务端 TLS record 原样转发给 Hub。
2. Hub MPC-TLS Engine 根据服务端 sequence 验证 GCM tag 并解密。
3. HTTP parser 在认证成功后才消费明文。
4. Coordinator 验证响应元数据并生成计费事件。
5. Gateway 将普通响应或 SSE 增量发送给 Consumer。
6. 响应结束后连接回到 `READY`；协议错误时直接进入 `CLOSED`。

## 6. 连接状态机

```text
NEW
  -> TCP_CONNECTING
  -> MPC_HANDSHAKING
  -> READY
  -> ENCRYPTING_REQUEST
  -> WAITING_RESPONSE
  -> READY
  -> DRAINING
  -> CLOSED
```

约束：

- 每条连接只能有一个状态变更执行者。
- 每条连接最多一个 in-flight 请求。
- TLS client/server sequence 分开维护，任何一侧不得回退。
- MPC 超时、TCP 重连、GCM tag 失败、消息序号不连续时销毁整个 session。
- TCP 断线后不能复用旧 session 的 MPC 状态。
- 请求是否可安全重试由 Coordinator 根据 delivery ACK 判断；一旦任何 TLS application
  record 的写入结果存在成功或超时歧义，就销毁 session，且不得自动重放同一任务。
- delivery ACK 只表示 Provider socket 写入完成，不表示上游应用已处理，也不能代替
  经过认证的响应和持久化 receipt 作为计费依据。

## 7. 数据所有权

| 数据 | Hub | Provider | Durable Store |
|---|---:|---:|---:|
| Consumer 请求和 prompt | 明文 | 可见 | 仅按产品策略保存 |
| Provider API key | 不可见 | 明文 | 禁止 |
| client write key | 仅份额 | 仅份额 | 禁止 |
| server write key | 完整 | 不可见 | 禁止 |
| 上游响应 | 明文 | 仅 TLS 密文 | 哈希/计费字段 |
| session sequence/nonce | 权威状态 | 镜像校验状态 | 不持久化秘密 |

## 8. 首期实现顺序

### M0：协议和网络骨架

- 定义控制协议、session ID、状态机和错误码。
- 完成 Provider Agent 到允许上游的原始 TCP relay。
- 使用假 MPC Engine 验证连接池、超时、SSE 和单 in-flight 约束。

### M1：TLS 1.2 MPC 握手

- 只支持一个经过实测的 ECDHE + AES-GCM cipher suite。
- 完成证书验证、Finished 验证和方向性密钥输出。
- 添加标准 TLS 实现对照测试和握手测试向量。

当前实现进度：已固定 TLSNotary/MPZ 依赖并引入记录了上游来源的受控
`tlsn`、`tlsn-mpc-tls`、`tlsn-deap`、`mpz-garble` 和 `mpz-garble-core` fork。
Hub follower 在进入 application traffic 前，会根据 MPC
认证的握手 records 独立核对 client/server Finished，并使用 Hub 提供的目标 DNS
名称与根证书验证证书链及当前 ECDHE key 的签名。只有这些检查全部成功，才产生
不可由 Provider 构造的 `VerifiedHandshake`；Hub 的 server write key/IV 解码句柄
必须消费该凭证后才能读取，而且只能读取一次。Go/Rust sidecar 无降级能力协商也已
完成。

server write key/IV 使用 MPZ garbled VM 的单向输出：Provider 侧只登记向 evaluator
发送 decode labels 的配对操作，不创建明文 future；Hub 侧只接收并持有明文 future，
且不会把已解码 bits 证明回 Provider。若 Provider 擅自改用普通双向 decode，flush
计数不匹配并中止 session，不能借此获得响应密钥。

本地 sidecar RPC 的 Go/Rust wire codec、角色绑定 hello、role-specific command
校验和跨语言二进制向量已经完成。Hub/Provider 均已有可运行的角色固定 Rust 进程：
只在账户私有目录内监听权限为 `0600` 的 Unix socket，不覆盖已有路径；session 绑定
创建它的本地连接，连接断开即销毁；流式输入限制为每帧 64 KiB、每次操作累计
16 MiB。Provider 的
`bind_credential` 使用严格 JSON，只接受本地 `credential_id`，显式或未知的
`api_key` 字段会被拒绝。Go 客户端已通过启动真实 Rust 进程的集成测试。

每个新 session 还会产生 32 字节随机本地 attachment capability。Hub 和 Provider
都可用独立 Unix RPC 连接附着长期双向 MPC channel；只有 Provider 能附着由 Go
Agent 经既有 egress policy 打开的 upstream channel，只有 Hub 能附着只读的已认证
response channel。授权失败与 session 不存在统一
返回 `attachment_rejected`，每类 channel 只能附着一次。attachment 使用每帧
64 KiB 的长连接流且支持单方向 half-close，不受一次性命令输入 16 MiB 总量限制；
Go 侧暴露为普通 `io.ReadWriteCloser`，可以直接接入双向 relay。capability 不得进入
日志，并在 Rust session 销毁时清零。

`run_handshake` 已接入真实 TLSNotary engine。Provider 必须同时具备 MPC 与 upstream
attachment，完成预处理后保留 live TLS connection 并返回 `handshake_running`；Hub
必须同时消费 MPC 与 response attachment，独立完成证书链、DNS、ECDHE 签名和 Finished 验证并取得单向
server key release 后才返回 `ready`。Coordinator 只能以 Hub 的成功结果作为连接池
可用判据。握手/预处理硬超时为 20 分钟，默认 warmer 超时为 25 分钟；同一 session 消费
channel 后不可重试；销毁 session
会终止 participant/driver task 并清零 Hub server traffic keys。

真实双参与方测试已使用非 ideal VM 完成 TLS 1.2 握手：正向用例在 TLS 尚未关闭时
验证 `test-server.io` 并取得单向 server key/IV；负向用例使用错误 DNS 身份，确认
无法产生授权释放对象。sidecar runtime 自身也有真实双参与方测试，确认 attachment
进入 engine 后 Hub 才能转为 `ready` 并取得非零响应密钥。M2 已在此 live connection
上接入 selective 请求加密；M3 已直接从 engine 捕获服务端密文 record，并由 Hub 本地
验证序号、TLS 版本、explicit nonce 和 AES-GCM tag 后输出 HTTP/1.1 明文。Provider 在
selective profile 下只处理 blind 占位 record，不获得响应明文。`feed_server_records`
保留为未实现的 v1 命令，防止另一条未绑定 live connection 的注入路径。
协议 v1 默认请求档位为 4 KiB/4 records，并提供 16k、64k、256k、1m、5m 精确档位；响应不执行 MPC AES/GHASH，单 session 上限为 16 MiB，
并通过 16-record 有界队列限制内存；慢 Consumer 填满队列时 session 失败关闭。证书、Finished
及单向输出分别有错误身份、边界/篡改、一次性消费和协议状态拒绝测试；未绑定 live
connection 的服务端 record 注入命令也有显式负向测试。

### M2：Selective 请求加密

- 实现固定 HTTP/1.1 模板和 secret layout。
- 实现公开 block 与秘密 block 两种 MPC 输出。
- 实现 GCM tag、sequence、explicit nonce 和一次性状态消费。
- 使用抓包与标准 TLS 服务端验证 record 互操作性。

当前进度：已实现首个固定 `openai_chat_completions_v1` adapter。Go
canonicalizer 不接收 Consumer headers，只接收目标 DNS 名、Provider 凭证长度和 JSON
对象；它拒绝重复 JSON key，确定性排序对象 key，并生成固定 path、固定 header 顺序、
规范十进制 Content-Length 以及全零凭证槽位。`secret_layout` 只由该模板推导，不再是
RPC 调用者可提供的字段。model 必须位于 canonical JSON 内并由 request hash 覆盖；
Go/Rust 两侧独立提取，成功 RPC 返回 `requested_model`，不接受未绑定的独立 model 参数。
流式模式也由同一 body 绑定：`stream` 缺省或为 false 时禁止携带 `stream_options`；
`stream=true` 时必须同时携带 `stream_options.include_usage=true`，成功 RPC 返回两侧
独立解析出的 `streaming`，防止用未绑定元数据选择计费路径。

Hub/Provider selective RPC 使用同一组严格元数据：`task_id`、adapter、
`credential_length` 和 canonical bytes 的 SHA-256。Rust Hub sidecar 会重新核对已认证
`server_name`、模板、凭证槽全零、JSON 对象、长度和 hash 后才允许进入 engine；Go 与
Rust 共用跨语言字节向量。当前 mixed-input AES-GCM selective circuit 已接入保留的
TLS 1.2 connection：Hub 拥有 canonical 公共字节，Provider 只拥有生成出的 credential
span；两侧各自安装一次性 plan，并在 TLS record 分片后逐 record 核对 range。严格模式
禁止应用数据绕过 selective 路径。Provider 通过本地 `CredentialResolver` 取得 API key，
带凭据的完整请求使用 zeroizing buffer，API key 不进入 Hub 或本地 RPC。

请求通常由 TLS 以 16 KiB application record 分片。只有与 credential span 重叠的首条
record 使用 mixed-input 电路；其后的纯 body record 被 plan 标记为 `Public`。Provider
必须提交与本地 canonical 模板逐字节一致的公开 record，否则 Hub 立即中止；验证通过后，
双方解码预热期间已完成求值、且与当前记录序号绑定的 AES-CTR keystream，再各自在本地与公开明文 XOR。
一次性会话的全部客户端 AES 块和 J0 掩码已前移到预热，凭证记录只解码密文，公共记录
才解码自己的 keystream；严格检查 16 KiB 分片与末片长度，禁止第二次请求及材料重用。
两端必须协商 `precomputed-client-aes` 能力。该路径省去大 body 的逐字节 mixed-input
选择电路和在线秘密输入，但没有消除 AES/GCM 总计算，所以预热时间、
CPU 和内存仍随请求上限线性增长。MPZ 的批量 context map 以 128 路有界窗口执行，避免
5 MiB 档位一次创建数十万个 mux child stream。

真实双参与方测试已覆盖握手、Hub `request_prepared`、Provider `request_delivered` 和
selective TLS write，且关闭时先等待 prover/verifier task 退出再释放 MPZ executor。
Provider sidecar 已支持从严格的 mode-0600 本地 JSON 文件加载凭据：拒绝软链接、宽松
权限、重复 ID、未知字段、HTTP header 控制字符和超长 key，并清零文件解析缓冲及凭据。
Provider 收到 `SIGHUP` 后会在锁外完整加载和验证新文件，再用短写锁原子交换 snapshot；
失败时保留旧 snapshot，已有 session 在实际 selective request dispatch 时解析 credential，
因此只会看到完整旧 generation 或完整新 generation。运维应先写入 mode-0600 临时文件，
原子 rename 覆盖后再发送 `SIGHUP`。Provider upstream attachment 已加入累计字节数和
SHA-256 前缀绑定的 delivery ACK；`request_delivered` 会等待本次 TLS 密文字节全部写入
Provider socket。Go/Rust capability 现在支持六个精确档位，从 4 KiB/4 request records
baseline 到 5 MiB/323 request records；各档均为 16 MiB response、6 online response
records。任一不一致都会拒绝协商，双方也会在进入 MPC 前拒绝超限 canonical request。
Coordinator 会按实际 canonical 长度跳过容量不足的 route。release 同机数据记录在
`benchmark-results.md`；5 MiB 全量资源基准和偶发握手停滞定位仍是上线前工作。

### M3：响应和流式转发

- 已完成：Hub 本地完成服务端 AES-GCM 验证和解密，并通过必需的 Hub-only response
  attachment 按 TLS record 顺序输出已认证明文。
- 已完成：Provider 不获得应用响应明文；响应 record 不执行 MPC AES/GHASH。
- 已完成：认证失败的 record 不会输出，record 队列有界且满时失败关闭。
- 已完成：Go 侧在整个 keep-alive attachment 上复用同一个标准库 HTTP/1.1 parser，
  支持 chunked、trailer 和跨 TLS record 的增量 SSE event，header/body/event 上限分别为
  64 KiB、16 MiB 和 1 MiB。
- 已完成：body 只有完整读到 EOF 才产生 SHA-256 complete outcome；截断、超限或提前
  close 会关闭响应路径，session 未确认 complete 时不能从 `WAITING_RESPONSE` 回到 `READY`。
- 已完成：提取 OpenAI response ID、model 和两套 token usage 命名，拒绝重复 JSON key、
  负数/小数、命名冲突和 total 不一致，避免歧义计费；SSE 全程固定 ID/model，必须收到
  `[DONE]`，最终 model 必须命中 adapter 显式允许的响应模型集合。
- 已完成：Consumer relay 对普通 JSON 先完整认证和校验再写出；SSE 逐 event 校验和 flush，
  但在认证 EOF、稳定 ID/model、最终 usage 和 durable receipt 全部成功前不会发送 `[DONE]`。
  非 2xx 上游响应完整认证后以不可计费结果转发。
- 已完成：Consumer 在 SSE 中途断开后，Hub 停止下游写入但继续认证并排空上游直到最终
  usage、`[DONE]` 和 EOF；有效响应仍生成可计费 receipt，不能通过拿到部分输出后断线逃费。
- 已完成：receipt 记录 task/Provider、请求和响应哈希、请求与实际模型、上游 request/response
  ID、状态码、body 大小和 usage；mode-0600 单写者 JSONL outbox 以 `task_id` 幂等，拒绝
  冲突证据，使用 SHA-256 hash chain 和每条 `fsync`，并可恢复崩溃产生的末尾半条记录。
- 已完成：参考账本在上游请求前按最大 input/output token 和版本化价格快照冻结 Consumer
  余额；receipt 到达后按实际 usage 结算，原子完成未使用额度退款、Provider 入账和平台费用。
  非计费响应及显式超时取消会全额解冻；超出预留 usage、绑定不一致和重复冲突均失败关闭。
- 已完成：部署层只暴露固定 chat-completions endpoint；Consumer key 在构造后只保留
  SHA-256 digest，按 Consumer 执行 token bucket、并发上限、请求大小和超时限制。
- 已完成：Coordinator 串联确定性 Provider 路由、余额预留、预热 session、双边请求绑定、
  响应验证和 receipt 结算；同一 task ID 不允许再次投递上游。
- 已完成：Provider 协议失败按权重计分并隔离，状态通过 mode-0600 原子文件跨 Hub 重启
  保留；状态持久化失败时 admission 失败关闭。

### M4：结算与审计

- 记录 `task_id`、Provider、上游身份、请求哈希、响应哈希、model、usage 和 request ID。
- 实现超时、失败退款、Provider 信誉和争议所需的内部审计记录。

当前已实现 durable receipt outbox、整数微单位价格计算和并发安全的参考账本状态机。
`Processor` 严格先持久化 receipt 再应用账本，并可在两步之间崩溃后重放全部 outbox；
funding transaction ID 与 task ID 均具备幂等/冲突语义。`DurableLedger` 将 funding、
reservation、settlement 和 cancellation 写入独立的 SHA-256 hash-chain 单写者日志，每条
状态变化在返回成功前 `fsync`，重启时重放完整账户状态。它不是 receipt outbox，也不会
从 receipt 猜测余额；大规模部署仍可用同一接口替换为数据库事务实现。

`tokenhive-hub` 与 `tokenhive-provider-agent` 已完成分机装配。控制与数据连接都由 Provider
发起，使用 mTLS 1.3 和 SPIFFE Provider 身份；数据连接复用 Provider 本地 sidecar RPC、
MPC attachment 与 allowlist 上游 TCP。模型上游连接的密码学目标仍严格为 TLS 1.2。

## 9. 第一版不做的事情

- TLS 1.3、HTTP/2 和 QUIC。
- Consumer 独立验证。
- 抵抗恶意 Hub 的主动安全 MPC。
- Provider 看不到 Consumer prompt。
- 动态解析任意上游 API；每种上游必须有单独的 canonical request adapter。
- 在没有基准测试之前承诺固定的毫秒级 MPC 延迟。
