# Go 业务接入

业务推荐依赖 `client` 包；需要在现有 Go 进程内运行 Hub 时，使用 `hub` 包。二者与命令行服务使用同一套实现。Rust sidecar 和 Provider Agent 继续作为独立进程部署，业务代码不接触 MPC 消息或 Provider 的真实凭证。

## 先跑完整验收

需要 Linux/Unix、Go 1.24+、仓库指定的 Rust 工具链、Python 3 和 OpenSSL。首次构建需要下载锁定依赖。

```sh
make smoke
```

这会构建两个 Go 服务与 release Rust sidecar，生成仅用于本地测试的 CA、证书和凭证，启动四个真实进程与本地 TLS 上游，验证 HTTP 普通/流式请求、Go SDK、幂等、防跨账号查询和回执落盘。没有付费上游调用。验收结束后关闭子进程，测试配置、日志、账本留在打印出的 `/tmp/tokenhive-demo-...` 目录。

```sh
make demo
# 保持服务运行；另一个终端：
go run ./examples/go/chat /tmp/tokenhive-demo-.../client.json
```

演示默认 4 KiB canonical HTTP 请求容量。容量包含 HTTP 头和凭证槽，不等于 JSON body 上限；演示的回答来自本地固定响应，实际加密与认证经过真实两方 MPC。

## 引入你的 Go 项目

当前 module 路径尚未发布到公共模块仓库。将本项目放入你的源码目录，然后在业务项目运行：

```sh
go mod edit -require=tokenhive.local/half-mpc-tls@v0.0.0
go mod edit -replace=tokenhive.local/half-mpc-tls=/absolute/path/to/half-mpc-tls
go mod tidy
```

在业务代码添加 import 后执行 `go mod tidy`。也可以将本仓库发布到你自己的 Go 模块地址后统一替换 module/import 路径。

## 普通调用

```go
import (
    "context"
    "time"
    "tokenhive.local/half-mpc-tls/client"
)

c, err := client.New(client.Config{
    BaseURL: "https://hub.example.com:8443/v1",
    APIKey:  consumerKey, // TokenHive 业务账号密钥，不是上游模型密钥
})
if err != nil { return err }
defer c.CloseIdleConnections()

ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
defer cancel()
result, err := c.Chat(ctx, client.ChatRequest{
    Model: "your-configured-model",
    Messages: []client.Message{{Role: "user", Content: "你好"}},
    MaxCompletionTokens: 128,
}, client.RequestOptions{IdempotencyKey: "order_123_answer_v1"})
if err != nil { return err }
// result.TaskID 关联业务订单与账本；result.Choices 为答案，Raw 保留完整响应。
```

`Client` 可以并发复用。应在应用启动时创建，应用退出时关闭空闲连接。默认复用 TLS 连接，最多保留 32 个同主机空闲连接，单请求总超时 5 分钟；传入 `HTTPClient` 可复用业务 transport、配置私有 CA 和超时。SDK 拒绝 HTTP 明文地址及所有重定向，不自动重试 POST。

`Message.Content` 可传字符串或 JSON 多模态内容；`Tools`、`ToolChoice`、`ResponseFormat` 为 `json.RawMessage`。`ChatRequest.Extra` 传上游扩展参数，不能覆盖 `model`、`stream` 等已有字段。具体字段和模型能力仍以所配置上游为准。完整可编译示例在 `examples/go/chat/main.go`。

## 流式调用

```go
stream, err := c.Stream(ctx, request, client.RequestOptions{
    IdempotencyKey: "order_123_answer_stream_v1",
})
if err != nil { return err }
defer stream.Close()
for {
    chunk, err := stream.Recv()
    if errors.Is(err, io.EOF) { break } // 只有收到已验证的 [DONE] 才表示完成
    if err != nil { return err }
    for _, choice := range chunk.Choices {
        // choice.Delta.Content、ToolCalls 等是增量；业务自行累计。
    }
}
```

需另外 import `errors` 和 `io`。SDK 自动请求 usage；网关也会对普通 HTTP 流式调用补齐 `stream_options.include_usage=true`，再进行 canonical hash 与 MPC 绑定。流中断返回错误，HTTP 200 本身不是完成标志。单个 Stream 由一个消费者读取；取消 context 可中断阻塞的 `Recv`。Consumer 断开后，Hub 可能继续验证和结算已经发生的上游消费。

## 超时、幂等与对账

业务应在首次发送前持久化一个操作 ID，使用同一个 `IdempotencyKey` 重试/查询同一操作。允许 1–128 个 ASCII 字母、数字、`-`、`_`。幂等键按 Consumer 账号隔离；同账号轮换 API key 不改变任务身份。

```go
status, err := c.TaskByKey(ctx, "order_123_answer_v1")
// 已拿到 result.TaskID 时也可 c.Task(ctx, result.TaskID)
```

| state | 含义 | 业务处理 |
| --- | --- | --- |
| `pending` | 已预留，尚无已提交的最终账务结果 | 继续查询或人工对账，不换新 key 重发 |
| `settled` | 已结算，包括非计费的上游错误 | 读取 charge/refund、token 用量；不重复派发 |
| `cancelled` | 任务失败，已退回预留 | 是否发起新业务操作由业务决定 |

`charge_micros`、`refund_micros` 和 `reserved_micros` 使用对应币种的百万分之一整数单位。查询不返回原始回答或 Provider 凭证/分账信息；系统没有响应缓存。账号外任务与不存在任务都返回 404。404 是查询当时没有记录，不保证一个仍在传输中的请求以后不会被接收；只能复用原 key 保持去重。

`errors.As(err, &apiError)` 可提取 `*client.APIError` 的 `StatusCode`、`Code`、`TaskID`、`RetryAfter`。常见状态：400 参数错误，401 鉴权失败，402 余额不足，409 已接收/幂等冲突，413 请求过大，429 限流，502 上游验证失败，503 容量不可用，504 超时。已提交 SSE 头之后发生错误会终止流，不发送伪造的成功 `[DONE]`。

崩溃后，已落盘回执会回放到帐本；只留下预留且没有完整回执的请求保持 `pending`，不能推断为未执行。升级前旧版本使用原始任务 ID，本版本使用账号作用域摘要；已有旧任务用原 TaskID 查询，升级窗口内不要将旧操作改用新的幂等映射重发。

## 嵌入现有 Go 服务

```go
import "tokenhive.local/half-mpc-tls/hub"

cfg, err := hub.LoadConfig("/etc/tokenhive/hub.json")
if err != nil { return err }
// 可按业务配置调整 cfg.APILimits、cfg.Routes 等；启动后不并发修改配置。
errCh := make(chan error, 1)
go func() { errCh <- hub.Run(appContext, cfg) }()
// 接入应用已有的生命周期和错误监督；退出时 cancel appContext 并等待 errCh。
```

`hub.Run` 管理本实例的三个监听地址、预计算池、持久化账本和退出清理，不安装进程 signal handler，也不调用 `os.Exit`。它启动自己的 HTTPS listener，应用现有 mux 不受影响；业务仍可用同进程内的 SDK 调用。不要在同一个 state directory 运行多个 Hub。`hub.Route`、`hub.PriceSnapshot`、`hub.Capacity`、`hub.CapacityProfile` 和 `hub.FundingConfig` 均可直接用于程序化配置，无需引用 `internal` 包。可编译入口见 `examples/go/embedded/main.go`。

## 配置与部署

从 `config/hub.example.json`、`config/provider.example.json` 开始：

1. 将 Hub 的监听证书和 Provider mTLS 证书接入你的 PKI。Provider 证书需包含 `spiffe://<trust_domain>/provider/<provider_id>` URI SAN；Agent 验证 Hub DNS。
2. Provider 在 mode-0600 JSON 中保存 `{"version":1,"credentials":{"openai-main":"真实上游密钥"}}`。Hub 的 `credential_length` 必须与该 ASCII 密钥字节数一致，Hub 配置不保存它的值。
3. 配置实际模型与允许返回的版本模型、报价、Consumer API key/余额；示例价格只是测试数字。`fundings.transaction_id` 幂等，不能用同一个 ID 修改金额。route 的 token maxima 是预留和结算上限；应覆盖真实输入与输出，业务同时明确设置模型输出限制，避免消费超过预留后需要对账。
4. 创建各自 mode-0700 runtime 目录和 Hub state directory；Hub 配置 mode 0600。sidecar socket mode 0600，因此本角色的 Go/Rust 进程用同一操作系统用户运行。
5. 启动两端 sidecar、Hub、Provider Agent。Provider 只向 Hub 发起 control/data 连接。SIGTERM 可清理 sidecar socket；异常强杀残留 socket 应在确认旧进程退出后由部署管理器处理，程序不会覆盖现有 socket。

```sh
# Hub 主机
rust/target/release/tokenhive-sidecar --role hub \
  --socket /run/tokenhive/hub-sidecar.sock --capacity baseline
bin/tokenhive-hub /etc/tokenhive/hub.json

# Provider 主机
rust/target/release/tokenhive-sidecar --role provider \
  --socket /run/tokenhive/provider-sidecar.sock --capacity baseline \
  --credential-file /etc/tokenhive/credentials.json
bin/tokenhive-provider-agent /etc/tokenhive/provider.json
```

默认使用内置公共 CA。私有模型服务可以在**两端** sidecar 设置 `--upstream-ca /path/to/ca.pem`：使用该单张 PEM CA 替换默认根集合，证书、DNS、签名和 Finished 验证保持开启。它不影响 Agent/Hub mTLS 信任配置，也不是跳过验证开关。

`api_limits` 配置每账号 `requests_per_second`、`burst`、`max_concurrent`。`body_read_timeout_seconds` 单独限制上传耗时，不截断后续长 SSE。SDK、网关和反向代理超时应协调；代理需关闭 SSE 缓冲。

小请求优先使用 baseline；大请求配置独立容量进程与 `hub_sidecar_sockets` / `sidecar_sockets`，两端和 route 必须完全匹配。六档可协商不代表六档均已完成部署容量验收。先测每档 warm 时间、RSS、实际 RTT，再调整 `target_ready`、`global_warm_concurrency`、`max_ready`、`max_leased` 和 `data_tunnels`；增加限流额度不能增加 MPC 预处理吞吐。

## 会话排队与过载处理

同一 Provider、凭证、目标、容量和 TLS 版本的会话池按进入 `Acquire` 队列的顺序分配库存。公平性不跨会话池，也不保证请求完成顺序。队列满时拒绝新等待者；等待者取消或超时后立即移出队列。补充库存只唤醒队首，后到请求不能越过队首抢库存。

| Hub JSON 配置 | 嵌入 Go 的字段 | 默认值 | 含义 |
| --- | --- | ---: | --- |
| `max_waiters` | `cfg.MaxWaiters` | 64 | 每个会话池的等待人数上限，不含已取得会话的请求 |
| `queue_wait_timeout_ms` | `cfg.QueueWaitTimeoutMS` | 10000 | 仅限等待会话的时间，不限制取得会话后的推理或 SSE 时长 |

省略或设为 0 使用默认值，负数无效。调用方 deadline 或 `request_timeout_seconds` 更早到期时优先生效。`api_limits.max_concurrent` 仍是每账号总并发上限，二者分别约束账号和会话池。冷启动如果需要超过 10 秒，应先等待 readiness，或按实际预热时间提高队列等待上限。

```go
cfg.MaxWaiters = 8
cfg.QueueWaitTimeoutMS = 2000 // 业务允许最多等 2 秒取得会话
```

队列拒绝返回 HTTP 503、`Retry-After: 1`，SDK 的 `*client.APIError.Code` 分别为 `queue_full` 和 `queue_timeout`。这些请求没有发送上游，执行路径会取消余额预留，不将拥塞记为 Provider 协议失败。业务可以据此限速、降级或安排稍后的新尝试；SDK 不自动重试。`Retry-After` 是退避提示，不是容量保证。

队列拒绝发生在任务预留之后，原幂等键已经绑定失败任务：直接用同一个键再次提交会得到 409。可通过 `Task` / `TaskByKey` 核对取消状态，再由业务显式创建使用新幂等键的新尝试。对于网络断开等结果不明确的错误，仍需先查询原任务，避免重复执行。

`/readyz` 只将扣除已排队需求后仍有库存的健康路由视为 ready；它仍然是瞬时快照，不预留会话。内部池统计包含 `Waiting`、`MaxWaiters`、`AcquireRejected`、`AcquireTimedOut` 和累计等待时间，供池管理和诊断使用。

## 启用 TLS 1.3

两端 sidecar 的启动命令均添加 `--tls-version 1.3`，对应 Hub route 添加 `"tls_version": "1.3"`。嵌入 Go 时可直接设置：

```go
for i := range cfg.Routes {
    cfg.Routes[i].TLSVersion = "1.3"
}
```

SDK 的 `Chat`、`Stream` 和任务查询无需改动。省略版本仍为 TLS 1.2。两端 sidecar、route 版本和容量必须匹配；配置不匹配不会创建上游会话，也不会回退。预热池按 TLS 版本隔离。目前 socket 映射按容量选择，每个容量对应的进程固定一种 TLS 版本；同一 socket 不能同时服务两种版本的路由。

TLS 1.3 支持 P-256、`TLS_AES_128_GCM_SHA256`、HTTP/1.1 完整握手。暂不支持 HRR、PSK/会话恢复、0-RTT、客户端证书或 HTTP/2；请确认实际上游兼容这个配置。凭证前缀和 KeyUpdate 使用 MPC，确认已实际写入上游后才向 Hub 释放新代客户端密钥，正文随后本地加密。密码协议仍依赖 Hub 遵守协议，详见 [引擎信任边界](../rust/crates/tls13/README.md)。

```sh
make smoke-tls13
make smoke-tls13-large
# 保持本地服务运行以接入自己的 Go 业务：
python3 scripts/demo.py --tls-version 1.3
```

## 中断、重启与账本恢复

Hub 启动时，先重放已经落盘的认证回执，再将剩余 pending 任务取消并退回预留余额，最后开放 API。取消事件也写入持久账本；重复重启不会重复退款，原幂等键继续绑定原任务，不自动重发请求。

**重启后取消不等于上游未执行。** 上游可能已经收到请求甚至产生费用，但 Hub 中断前没有留下可验证回执。本系统不会凭不完整响应扣费或发放 Provider 收益。业务遇到结果不明确的断连，应先查原任务；不能仅凭 cancelled 状态就自动换幂等键重试。明确的 `queue_full` / `queue_timeout` 则发生在上游发送之前。

Provider、sidecar 或数据连接失效时，Hub 会关闭对应会话的全部附件，解除阻塞中的响应读取，未完成认证的任务会退款。客户端自己中途断开时，已开始的响应仍尝试读完并结算，但不超过原请求 deadline；队列超时和整次请求 deadline 是不同限制。对流式调用，已发送 HTTP 200 后发生故障会表现为缺少 DONE 或流读取错误，不能仅凭响应头认定成功。

sidecar 被 SIGKILL 后可能留下 UDS socket。现有服务拒绝覆盖任意已有路径，部署 supervisor 需要确认旧进程已退出，再清理它自己管理的残留 socket 并重启。验证脚本显式执行了该步骤，因此测得恢复时间包括 supervisor 的操作，不代表进程有自行拉起能力。

连续验证失败会累积 Provider 健康分，达到阈值后默认隔离 5 分钟，状态持久化。即使连接恢复，隔离期间 readiness 仍可能为 503；运维需区分通信恢复与健康策略允许重新接单。

## HTTP 接口

| 接口 | 鉴权 | 用途 |
| --- | --- | --- |
| `GET /healthz` | 无 | 进程存活 |
| `GET /readyz` | Consumer key | 至少一个健康路由扣除排队需求后仍有 ready 会话时 200，否则 503；是瞬时快照 |
| `GET /v1/models` | Consumer key | 配置中的模型列表，不承诺每个模型当前都有库存 |
| `POST /v1/chat/completions` | Consumer key | JSON 或 SSE |
| `GET /v1/tasks/{task_id}` | Consumer key | 本账号任务状态 |
| `GET /v1/tasks/by-key/{idempotency_key}` | Consumer key | 按本账号原幂等键查询 |

本地测试覆盖的容量与命令见 [集成验收记录](integration-validation.md)。真实模型服务兼容性、部署吞吐和尾延迟仍需在目标上游、网络和硬件上验收；本地功能通过不等于生产 SLO。
