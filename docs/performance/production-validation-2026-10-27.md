# 本机持续负载与恢复验证

测量开始：2026-10-27T09:14:43Z；CPU：Apple M3 Pro，可用逻辑 CPU：11。

同一部署执行 3 段各 300 秒负载。真实四进程、合成 HTTPS 上游、生成凭证；不是付费模型、跨机或 24 小时验收。

## 故障恢复

| 场景 | 观察耗时 | 任务状态 |
| --- | ---: | --- |
| hub-kill-during-sse | 1.550 秒 | cancelled |
| agent-kill-during-sse | 0.353 秒 | cancelled |
| hub-sidecar-kill-during-sse | 0.576 秒 | cancelled |
| provider-sidecar-kill-during-sse | 0.016 秒 | cancelled |
| data-partition-3s | 10.822 秒 | cancelled |
| consumer-disconnect-drains-and-settles | 响应读完后 | settled |
| response-deadline-25s | 25.018 秒 | cancelled |
| graceful-hub-restart-retains-settlement | 1.482 秒 | 保持原结算 |

恢复耗时是本次观察，不是 SLA。重启由测试 supervisor 执行，数据分区是应用层断链，不是包级丢包模拟。
故障账本：{"reserved": 34, "settled": 28, "cancelled": 6, "pending": 0, "receipts": 28}。

## 持续负载

| 场景 | 成功/失败/未发送 | 首内容 P50/P95/P99 ms | 稳态完成/s | 四进程 CPU 核数 | RSS 峰值 MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| json-rate1 | 300/0/0 | 237/251/261 | 1.00 | 0.86 | 325 |
| sse-rate1 | 300/0/0 | 220/231/239 | 1.00 | 0.86 | 334 |
| saturated-json-c4 | 2328/0/0 | 511/585/637 | 7.76 | 6.81 | 505 |

持续负载账本：{"reserved": 2928, "settled": 2928, "cancelled": 0, "pending": 0, "receipts": 2928}。

成功延迟分位数只统计成功请求；失败和未发送数量单列。JSON 首内容指完整 JSON，SSE 指首个内容事件。

## 分钟资源窗口

采样方法：ps time/rss; vm_stat free+inactive estimate; threads/fds not sampled。缺失的 FD/线程指标标为 n/a，不补零。RSS 合计可能重复计算共享页，且账本任务索引随任务数增长。

| 场景/分钟 | 成功/失败 | 首内容 P95 ms | RSS 合计中位数 MiB | Hub / Agent / Hub sidecar / Provider sidecar RSS 中位数 MiB | 同顺序 FD 中位数 |
| --- | ---: | ---: | ---: | --- | --- |
| json-rate1 / 1 | 60/0 | 249 | 312 | 23.2 / 22.5 / 131.6 / 135.5 | n/a / n/a / n/a / n/a |
| json-rate1 / 2 | 60/0 | 242 | 319 | 23.6 / 22.7 / 131.5 / 141.0 | n/a / n/a / n/a / n/a |
| json-rate1 / 3 | 60/0 | 245 | 322 | 23.7 / 22.8 / 132.7 / 142.5 | n/a / n/a / n/a / n/a |
| json-rate1 / 4 | 60/0 | 250 | 292 | 23.8 / 23.0 / 117.8 / 127.6 | n/a / n/a / n/a / n/a |
| json-rate1 / 5 | 60/0 | 253 | 294 | 24.0 / 23.1 / 118.3 / 128.2 | n/a / n/a / n/a / n/a |
| sse-rate1 / 1 | 60/0 | 230 | 297 | 29.5 / 22.5 / 115.4 / 129.7 | n/a / n/a / n/a / n/a |
| sse-rate1 / 2 | 60/0 | 231 | 311 | 34.1 / 22.6 / 123.6 / 131.2 | n/a / n/a / n/a / n/a |
| sse-rate1 / 3 | 60/0 | 230 | 314 | 34.1 / 22.6 / 129.4 / 128.3 | n/a / n/a / n/a / n/a |
| sse-rate1 / 4 | 60/0 | 228 | 333 | 51.4 / 22.7 / 130.2 / 128.7 | n/a / n/a / n/a / n/a |
| sse-rate1 / 5 | 60/0 | 235 | 316 | 31.9 / 22.7 / 130.9 / 130.4 | n/a / n/a / n/a / n/a |
| saturated-json-c4 / 1 | 458/0 | 577 | 456 | 54.1 / 24.8 / 192.0 / 185.3 | n/a / n/a / n/a / n/a |
| saturated-json-c4 / 2 | 454/0 | 599 | 476 | 58.5 / 25.0 / 200.4 / 192.1 | n/a / n/a / n/a / n/a |
| saturated-json-c4 / 3 | 481/0 | 558 | 492 | 58.7 / 25.3 / 207.4 / 200.8 | n/a / n/a / n/a / n/a |
| saturated-json-c4 / 4 | 466/0 | 584 | 452 | 49.9 / 24.4 / 190.2 / 184.8 | n/a / n/a / n/a / n/a |
| saturated-json-c4 / 5 | 469/0 | 630 | 469 | 50.8 / 24.7 / 192.4 / 201.1 | n/a / n/a / n/a / n/a |

资源曲线用于观察本次窗口；不能凭 FD 稳定或 RSS 首尾差值独立判定泄漏。

## Go CPU profile

MPC 转发累计占比：32.59%；两个 sidecar 占四进程 CPU 约 58.0%。累计路径有包含关系，不可相加。

四进程 CPU 秒数：{"hub-sidecar": 114.08, "provider-sidecar": 131.17999999999998, "hub": 92.67, "agent": 84.97}；成功 468，失败 0。

[平面采样](production-validation-2026-10-27-cpu-top.txt) · [累计采样](production-validation-2026-10-27-cpu-cumulative.txt) · [脱敏数据](production-validation-2026-10-27.json)。Rust 分阶段及原生栈另由 profile-warm.py 记录，本报告不假定其已执行。

## 一致性与范围

已检查三个阶段的构建产物 SHA-256 一致、清理无异常、任务无重复结算及未决 pending。具体失败请求仍保留在数据中；本报告不会自动声称 Go/Rust 测试或生产稳定性通过。

原始目录：soak `/tmp/tokenhive-validation-mnlvmtr6`，faults `/tmp/tokenhive-validation-0zpwezv1`，profile `/tmp/tokenhive-validation-r9cl69xm`。原目录含生成配置与私钥，分享脱敏导出即可。

真实 Provider 出口、真实凭证与模型、跨机 RTT/带宽/丢包和长时间运行需要独立准入验证。
