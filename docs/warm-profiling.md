# 预热分阶段测量与公网探测

更新：2026-10-27。工具与实际结果分开记录；工具存在不代表某个环境已通过验收。

## 构建与本地测量

```sh
make build
go build -trimpath -o bin/tokenhive-loadtest ./scripts/loadtest
python3 scripts/profile-warm.py --tls-version 1.3 --seconds 30
python3 scripts/profile-warm.py --tls-version 1.2 --capacity baseline --seconds 30
```

脚本启动真实 Hub、Provider Agent 和双方 sidecar，使用临时 CA、生成凭证、固定 usage 的本地 HTTPS 上游和公开 Go SDK。它不调用付费模型。生成文件位于权限受限的临时目录；`summary.json` 用于分享，包含生成配置/私钥的整个原始目录不用于公开发布。

`TOKENHIVE_PROFILE_STAGES=1` 为 Rust 引擎启用 JSONL 诊断。默认关闭，日志只包含进程 ID、单调区间 ID、固定角色/阶段名称、Unix 时间、墙钟和进程 CPU 增量，不包含 credential ID、task ID、请求/响应正文或 traffic secret。提前错误和取消区间标记为未完成；汇总只统计完成区间。退出进程前未落完整日志的区间不补造结果。

| 阶段 | 含义与限制 |
| --- | --- |
| `tls12_preprocessing` | Provider commit / Hub accept 中的准备与双方等待；先于 Provider connect |
| `tls12_upstream_authentication` | Hub 驱动并等待真实上游认证；不把全部时间归为证书 CPU |
| `tls13_key_exchange_setup` | KE/OT setup 和双方准备 |
| `tls13_ecdhe_shares` | 服务器公钥已知后的份额计算与输入赋值 |
| `tls13_handshake_schedule` | Hub 握手 HKDF 电路构造与所需秘密输出执行 |
| `tls13_server_authentication` | 接收握手、证书链/DNS/签名/Finished 验证，包含网络等待 |
| `tls13_application_schedule` | 应用密钥派生、固定凭证 AES 计划与相关输出求值 |
| `tls13_vm_execute` | VM 执行，含 garbling、OT、通信；可能嵌套在其他阶段 |
| `tls13_credential_encryption` | 固定前缀及 KeyUpdate 的在线 MPC 部分 |

CPU 数据使用 [`ProcessTime`](https://docs.rs/cpu-time/1.0.0/cpu_time/struct.ProcessTime.html) 的全进程 CPU 时钟。它能反映线程池真实 CPU 消耗，但包括同一进程其他并发任务；既不是当前 async task 独占 CPU，也不是每个算法的独立计数。嵌套和重叠阶段不能相加，Hub/Provider 的墙钟也不能相加当端到端时延。精确归因 OT、HKDF、AES 与 garbling 须结合原生调用栈，不从阶段名直接推断百分比。

macOS 同时运行 `sample` 收集双方 sidecar 的原生栈；它包括等待线程，不等价于仅采样正在 CPU 执行的线程。Linux 使用 `perf record`，主机权限不够时保留明确失败状态，不修改系统安全参数。未安装/采样失败不能宣称完成原生 profile。单机总 CPU、RSS 与阶段 CPU 分别报告，测量方法和宿主机型号随报告保存。

当前原始 Linux 压测为约两逻辑 CPU 的共享 EPYC 环境，不能和本机 Apple Silicon 结果直接作优化前后速度比较。工具默认仅作当前构建归因及正确性验收，不产生跨硬件的提速倍数。

## 无真实凭证的公网验证

```sh
cargo build --manifest-path rust/Cargo.toml --locked --release \
  -p tokenhive-tls13 --example upstream_probe
python3 scripts/probe-upstream.py --host api.openai.com --path /v1/models --samples 2
python3 scripts/probe-upstream.py --host www.cloudflare.com --path /cdn-cgi/trace --samples 2
python3 scripts/clienthello-fingerprint.py /tmp/ACTUAL_CAPTURE/clienthello-0.bin
```

该 Rust example 使用与生产相同的两方 MPC 握手和 `Hub::request` KeyUpdate 路径。它只发送无 Authorization 的 GET，秘密槽填入公开测试 header 的常量，不读取任何环境 API key。TLS 证书和 DNS 验证保持开启，结果只记录 HTTP 状态、阶段、期限、认证 close 与 ClientHello，不记录响应正文。普通 TLS 1.3 GET 仅作基础网络对照，其 ClientHello 不同，不能用于独立归因风控。

捕获的是本项目实际发出的首个明文 ClientHello。解析器提取公开 cipher、extension 顺序、groups、signature algorithms 和 ALPN，并计算 JA3/JA4。Go/Rust 单元测试使用的 `testdata/tls13-clienthello-v1.hex` 是与生成器逐字节匹配的公开合成 fixture；它的占位 key share 不用于网络握手，不能代替实际捕获证据。

本探测只覆盖运行机器的出口和当时命中的上游节点。当前 pull relay 不能证明服务器没有在后续头写完前提前响应；401/403 尤其不能证明整个跨代请求已被消费。即使接收完整认证 HTTP，也不等于真实凭证、模型、SSE usage 与 Provider 部署准入通过。部署验收标准见 [ADR 0004](adr/0004-upstream-compatibility-validation.md)。

## 决策使用

两层库存与 TLS 1.2 复用的评估已完成：[ADR 0002](adr/0002-precomputation-and-one-shot-sessions.md)。在阶段数据和真实空闲损耗证明收益前，不新增两套秘密材料池，也不扩大 MaxUses。连接多路复用和协议范围的当前决定分别见 [ADR 0003](adr/0003-session-transport-isolation.md)、[ADR 0005](adr/0005-protocol-compatibility.md)。后续实际结果单独写入 `docs/performance/`，保留失败样本和验证范围。
