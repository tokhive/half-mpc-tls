# TLS 1.3 四进程性能压测

测量时间：2026-10-26T06:07:10Z。本报告记录实测结果，不将独立引擎计时当成业务端到端延迟。

## 环境和方法

- CPU：AMD EPYC 7R32，进程可使用 2 个逻辑 CPU；内存 3.74 GiB。共享开发主机，未隔离其他系统负载。
- 被测服务为 release Rust Hub/Provider sidecar、Go Hub、Go Provider Agent 四个真实进程；SDK 发压端与 HTTPS 上游也在同一主机。
- 上游使用临时 CA 和虚构凭证，TLS 1.3 / P-256 / AES-128-GCM。真实 MPC、双向 mTLS、Provider 本地投递 ACK、鉴权、规范化、回执和账本 fsync 全部开启。
- 上游收到完整请求后固定等待 200 ms。JSON 返回约 2.5 KiB 文本；SSE 输出 40 个内容事件，间隔 20 ms，随后输出 usage 和 DONE。用量是固定测试值，不代表真实模型分词或推理。
- 发压使用公开 Go SDK 和复用 HTTP/1.1 连接。每个逻辑请求使用唯一幂等键，不主动重试。SDK、上传、排队、加密、响应校验及结算开销均在请求计时内。
- 大 prompt 场景的上游仍固定等待 200 ms，不模拟随 token 数增长的真实模型 prefill；这些端到端数字不能代替实际长上下文模型延迟。
- 主配置：target_ready=2、max_ready=4、单 key/全局预热并发=2、max_leased=16、data_tunnels=16。测试账号限流调整为 100 RPS / 32 并发，避免默认 2 RPS 限流掩盖服务容量。
- 队列配置：max_waiters=4、queue_wait_timeout_ms=1500；FIFO 版本的队列超时独立于请求执行超时。
- 服务请求超时 25 秒，SDK 超时 30 秒。错误请求保留在原始数据中；延迟分位数仅统计成功请求，必须结合错误/丢弃计数解读。
- 同一容量的场景依次运行并保留预热池/自动扩容状态；切换容量或加入延迟时重启部署。每个场景只有一轮，前后对比不构成统计显著性结论。
- 固定并发是闭环：完成后再发下一请求。rate 场景固定到达速率，最多 16 个在途；满额到达记作 dropped，不将其隐藏或算成功。
- ready-json-c1 每次先轮询 readyz，再单独计时请求；检查和等待不计入单请求延迟，但计入整轮耗时。readyz 为瞬时快照，不等于拿到排他的会话租约。其他场景仅在启动前检查一次 readiness。
- delay5 场景仅在 Provider→Hub 数据连接上加入每方向 5 ms 的流水字节流延迟。它不是公网测试，也不模拟带宽限制、丢包、重传或 TCP 拥塞窗口。
- 每 250 ms 读取四个服务进程的 /proc CPU 与 RSS。RSS 相加可能重复计入共享页，不是 PSS；采样峰值不是精确瞬时内存峰值。发压端、上游和延迟代理不计入四服务 CPU/RSS，但在原始资源采样中保留。

## 延迟与吞吐

时间单位为毫秒。JSON 的“首内容”是 SDK 收到并解析完整 JSON；SSE 的“首内容”是 SDK 收到第一个非空内容事件。二者分别解读。

“稳态完成/s”统计去掉开头 10 秒后的发压窗口内成功完成数，不含最后停止发新请求后的排空；短于 30 秒时去掉开头 1/3。受限于短测量窗口，不是长期容量保证。ready 场景可能按请求数提前结束，使用整轮完成/s，不能当作持续负载。

| 场景 | 成功/失败/丢弃 | 稳态完成/s | 首内容 P50 | P95 | P99 | 总耗时 P95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| json-rate4 | 77/163/0 | 1.24 | 1595 | 1785 | 1969 | 1785 |

baseline prompt 为 1,024 字节；1m 为 1,047,552 字节；5m 为 5,241,856 字节，另有 JSON 和 HTTP 开销。cN 表示 N 个闭环 worker；rateN 表示每秒固定发起 N 次、最多 16 个在途。

## 资源与流式稳定性

CPU 核数是四服务 CPU 时间之和除以采样窗口；2.0 代表约占满本机两个 CPU。SSE 的间隔 P95 是“每请求最大相邻内容事件间隔”的 P95，不是所有事件间隔混合后的 P95。

| 场景 | 平均 CPU 核数 | 四进程峰值 RSS MiB | TTFB P95 ms | SSE 最大间隔 P95 ms | 上游请求/落盘回执 |
| --- | ---: | ---: | ---: | ---: | ---: |
| json-rate4 | 1.78 | 301 | 1784 | — | 77/77 |

直连场景绕过网关，因此没有网关回执。成功网关请求必须已经落盘；如果客户端失败，仍需单独检查其是否已经到达上游或结算。

## 错误明细

- json-rate4: {"TokenHive HTTP 503 (queue_full): Provider wait queue is full": 88, "TokenHive HTTP 503 (queue_timeout): Provider queue wait timed out": 75}；发压端满额丢弃 0 次。

## 可复现与证据

```sh
make bench-e2e
# 或指定每场景时长（固定速率场景至少 60 秒）：
python3 scripts/benchmark-e2e.py --seconds 45
python3 scripts/report-e2e.py /tmp/tokenhive-perf-XXXX --output docs/performance/my-run
```

原始进程日志、逐请求数据和 250 ms 资源采样：`/tmp/tokenhive-perf-7dz7qaeo`。

可分享的逐请求测量和二进制 SHA-256：[JSON 数据](e2e-2026-10-26-overload.json)。不包含临时凭证、证书私钥或业务请求内容。

进程退出和 socket 清理异常：`[]`。

## 结论适用范围

这比独立加密微基准更接近实际业务路径，但仍是同机合成上游。分位数使用 nearest-rank；每场景样本数有限，P99 常接近最大值，不应视为稳定 SLO。未测多 Provider 横向扩展、真实模型推理、跨公网丢包、长时间运行泄漏或故障恢复。
