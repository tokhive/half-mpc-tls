# 本机生产前验证：持续负载与故障恢复

测量开始：2026-10-26T06:59:39Z。2 个逻辑 CPU，真实四进程、TLS 1.3、合成 HTTPS 上游。

## 验收范围

本轮用于检验本机稳定性、错误退出、重连和账本一致性。先复现并修复三个故障，再以相同最终二进制完成故障复测、Go CPU profile 和连续负载。仅完成 15 分钟连续负载，不是 24 小时或多天 soak；不包含真实模型、跨机公网、带宽限制或丢包。用户已明确将跨机验证留到后续。

## 实际发现与修复

1. **Hub 崩溃遗留 pending 余额预留。** 在已收到 SSE 内容后 SIGKILL Hub，原实现重启后任务仍 pending。启动流程现先重放持久回执，再取消其余中断任务并退款，最后开放 API；重复重启不重复退款。已有回执必须优先结算，不能先批量退款。
2. **传输故障留下阻塞的响应读取。** Agent 在流式处理中退出后，原实现只取消转发 context，客户端等到 35 秒读取超时，任务仍 pending。现对失败会话异步关闭全部附件，解除响应阻塞；初始化时保持任务计数非零，防止首个任务立即失败时与其余任务注册竞争。
3. **响应阶段未受总请求期限约束。** 现将原请求 deadline 绑定到会话销毁，客户端断开后的继续读取和结算也不超过该期限。合成上游持续输出的测试在约 25 秒被终止、退款，没有输出 DONE。

Hub 重启后的取消表示缺少可靠结算证据，不表示上游未处理请求。上游可能已经产生费用；本地不会对不完整响应计费。原任务键保留，SDK 不会自动重新执行。

## 故障复测

| 场景 | 恢复/结束时间 | 账本结果 |
| --- | ---: | --- |
| hub-kill-during-sse | 2.880 秒 | cancelled |
| agent-kill-during-sse | 2.392 秒 | cancelled |
| hub-sidecar-kill-during-sse | 2.330 秒 | cancelled |
| provider-sidecar-kill-during-sse | 2.241 秒 | cancelled |
| data-partition-3s | 9.507 秒 | cancelled |
| consumer-disconnect-drains-and-settles | 响应读完后 | settled |
| response-deadline-25s | 25.007 秒 | cancelled |
| graceful-hub-restart-retains-settlement | 2.146 秒 | 原结算保持不变 |

恢复时间是单次观察，不是恢复 SLA。每个强制重启均发生在收到首条真实 SSE 内容之后；不是空闲进程重启。进程由测试 supervisor 拉起，sidecar 的残留 UDS 由 supervisor 在确认旧进程退出后清理。产品进程自身没有自动拉起功能。
数据链路中断覆盖所有 Provider 数据 TCP 连接，拒绝新连接 3 秒后恢复；控制连接保留。表中时间包含这 3 秒，属于应用层断链模拟，不是丢包模拟。每次强制重启后完成 6 个成功请求，数据链路恢复后完成 3 个成功请求。客户端主动断流的响应会继续认证读完并结算。
故障场景账本：预留 34，结算 28，取消 6，pending 0；回执 28。同一任务不重复结算、结算与取消集合不相交。

**健康策略观察：** 最初连续注入多个故障、每次仅完成 3 个成功请求时，累计健康分达到 11，触发已有的 5 分钟隔离，ready 等待超过 120 秒。这是持久化隔离策略，不是数据连接没有重连。最终复测在每次故障后完成 6 个成功请求以恢复健康分，区分单次网络恢复与连续失败隔离；没有降低健康校验或隔离阈值。

## 15 分钟连续负载

同一部署连续执行三段各 300 秒负载，期间不重启或清空池。上游首响应等待 200 ms；SSE 为 40 个内容事件、间隔 20 ms；小请求为 1 KiB prompt。预热目标 2、上限 4、预热并发 2，等待队列上限 64、等待 10 秒，总请求期限 25 秒。

| 场景 | 成功/失败/发压端未发送 | 首内容 P50/P95/P99 ms | 稳态完成/s | 四进程 CPU 核数 | RSS 峰值 MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| json-rate1 | 300/0/0 | 250/278/311 | 1.00 | 1.48 | 268 |
| sse-rate1 | 300/0/0 | 236/258/290 | 1.00 | 1.49 | 350 |
| saturated-json-c4 | 410/0/0 | 2910/3349/3533 | 1.35 | 1.87 | 444 |

持续负载账本：预留 1010，结算 1010，取消 0，pending 0；回执 1010。

成功分位数不包含失败；所有失败和未发送均单列。JSON 首内容表示完整 JSON 解析完成，SSE 表示首个非空内容事件。稳态完成速率去掉每段前 10 秒和末尾排空。

## 分钟窗口与资源

每 250 ms 采样四服务的 RSS、文件描述符和线程数。RSS 合计可能重复计入共享页；未包含上游、负载生成器和 Python harness。窗口按请求开始时间划分；内存是该分钟采样中位数。不同阶段工作负载及预热库存不同，不能只比较首尾 RSS 就判定泄漏。持久账本任务索引本身也随任务数增长。

| 场景/分钟 | 成功/失败 | 首内容 P95 ms | 合计 RSS 中位数 MiB | Hub / Agent / 两 sidecar FD 中位数 |
| --- | ---: | ---: | ---: | --- |
| json-rate1 / 1 | 60/0 | 265 | 177 | 35 / 30 / 16 / 16 |
| json-rate1 / 2 | 60/0 | 299 | 194 | 35.0 / 30.0 / 16.0 / 16.0 |
| json-rate1 / 3 | 60/0 | 271 | 207 | 35.0 / 30.0 / 16.0 / 16.0 |
| json-rate1 / 4 | 60/0 | 270 | 208 | 35 / 30 / 16 / 16 |
| json-rate1 / 5 | 60/0 | 276 | 219 | 35.0 / 30.0 / 16.0 / 16.0 |
| sse-rate1 / 1 | 60/0 | 258 | 246 | 38 / 34 / 19 / 19 |
| sse-rate1 / 2 | 60/0 | 266 | 261 | 38 / 34 / 19 / 19 |
| sse-rate1 / 3 | 60/0 | 251 | 263 | 38 / 34 / 19 / 19 |
| sse-rate1 / 4 | 60/0 | 248 | 274 | 38 / 34 / 19 / 19 |
| sse-rate1 / 5 | 60/0 | 258 | 285 | 38 / 34 / 19 / 19 |
| saturated-json-c4 / 1 | 88/0 | 3020 | 291 | 38.0 / 30.0 / 16.0 / 16.0 |
| saturated-json-c4 / 2 | 82/0 | 3008 | 303 | 38 / 30 / 16 / 16 |
| saturated-json-c4 / 3 | 78/0 | 3497 | 313 | 38 / 30 / 16 / 16 |
| saturated-json-c4 / 4 | 82/0 | 3241 | 328 | 38 / 30 / 16 / 16 |
| saturated-json-c4 / 5 | 80/0 | 3444 | 338 | 38 / 30 / 16 / 16 |

本轮观察到持续内存增长：Agent 每分钟 RSS 中位数从约 15 MiB 升至 105 MiB，四服务合计中位数从 177 MiB 升至 338 MiB，峰值 444 MiB。各阶段 FD 中位数保持稳定，不能据此排除 goroutine/连接对象泄漏。代码核查发现 internal/tunnel/provider.go 的 Serve 在每次连接建立时创建等待 Agent 全局 context 结束的 goroutine，连接退出不会移除它。新增回归实测 128 个已关闭连接留下 128 个 goroutine，测试失败，日志 /tmp/tokenhive-agent-leak-before.log。该问题尚未修复，不能判定长期稳定性通过。用户随后要求停止测试，本轮到此停止，未启动下一轮压测。

## CPU profile

独立 60 秒、4 并发场景，通过公开 hub.RunFile 包装器采集 Go CPU profile，没有打开调试 HTTP 端口。系统 perf_event_paranoid=4 禁止 perf，未改变系统设置；本轮没有 Rust 原生调用栈采样，也没有声称完成全部 MPC 内部阶段的 CPU 归因。

Hub CPU 样本中，经 MPC 转发路径 relayMPC 的累计占比为 64.91%；两个 Rust sidecar 合计占四服务 CPU 时间约 65.7%。Go 的下一优化方向是转发路径中的帧分配、复制和 I/O；Rust 仍需原生 profile 才能继续分解。

四进程 CPU 秒数：{"hub-sidecar": 34.08, "provider-sidecar": 42.86, "hub": 23.32, "agent": 16.889999999999997}。该 profile 场景成功 84、失败 0。

[Hub CPU 平面采样](production-validation-2026-10-26-cpu-top.txt) · [累计调用路径](production-validation-2026-10-26-cpu-cumulative.txt)。累计路径有包含关系，百分比不可相加。原始 pprof 保存在 `/tmp/tokenhive-validation-pmdgb6dl` 下。

## 校验与复现

Go race 全套、go vet、默认 TLS 1.2 四进程 JSON/SSE/SDK 冒烟均通过。新增回归覆盖已落盘未结算回执与无回执任务的恢复顺序、重复重启和退款幂等性、断链解除响应阻塞、任务初始化与关闭竞争、响应期限及健康分处理。

```sh
make build
go build -trimpath -o bin/tokenhive-loadtest ./scripts/loadtest
go build -trimpath -o bin/tokenhive-profile-hub ./scripts/profilehub
python3 scripts/validate-production.py --mode faults
python3 scripts/validate-production.py --mode profile
python3 scripts/validate-production.py --mode soak --seconds 300
```

原始数据：持续负载 `/tmp/tokenhive-validation-bzfuqtgt`；故障 `/tmp/tokenhive-validation-nqz93maq`；CPU `/tmp/tokenhive-validation-pmdgb6dl`。三个阶段记录的构建产物 SHA-256 一致；profile 使用独立诊断包装器，记录在 [JSON 导出](production-validation-2026-10-26.json)。被测进程退出和 socket 清理均通过。

本轮未通过长期稳定性验收：Agent 连接生命周期泄漏待修复。生产容量验收仍缺少跨机实际 RTT、真实模型、大规模并发、24 小时以上运行和生产 supervisor 部署验证。吞吐提升需要另行优化；本轮优先修复了可用性与结算恢复缺口。
