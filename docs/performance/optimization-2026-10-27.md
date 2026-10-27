# TLS 1.3 密钥计划优化与验证

2026-10-27；Apple M3 Pro，11 个逻辑 CPU，36 GiB 内存，共享宿主。安全模型为可信 Hub、可恶意 Provider。

## 改动与依据

原生栈采样可见 garbling、AES 和序列化工作；语义阶段计时显示握手与应用密钥计划占据主要准备时间，ECDHE 份额阶段只有约 1 ms。它们是两种不同维度：阶段计时不能进一步给出 OT、garbling、PRF 各自独占的精确 CPU 百分比。

同一 VM 中，同一 HMAC key 的 ipad/opad SHA-256 首块只求值一次，后续 label/context 从秘密压缩状态分叉。固定计划压缩块从 40 降到 30。不输出状态明文，不跨会话缓存，不复用 OT、nonce、记录或随机性。安全、向量与混版本拒绝测试见 [ADR 0007](../adr/0007-session-local-hmac-prefix-states.md)。

TLS 1.3 新部署默认一个 `5m` 档位，固定凭证前缀最多 1 KiB；TLS 1.2 和显式旧档位行为保留。会话仍一次请求一次消费，未通过放宽状态机提高吞吐。

## 同机单轮前后对照

两次均为 release 构建、TLS 1.3、共享 `5m` 档位、Go SDK 并发 4、1 KiB prompt、JSON、30 秒负载、合成 HTTPS 上游。启用阶段计时，对两个 sidecar 使用 macOS `sample`，间隔 10 ms。稳态完成量按最后 20 秒窗口统计。二进制 SHA、阶段样本数与采样状态见 [数据](optimization-2026-10-27.json)。优化前 SHA 是运行结束后、重新构建前记录的。

| 指标 | 优化前 | 最终构建 | 观察变化 |
| --- | ---: | ---: | ---: |
| 成功 / 失败 | 113 / 0 | 126 / 0 | 两轮无失败 |
| 稳态完成量 / 秒 | 3.55 | 4.10 | +15.5% |
| 首内容 P50 ms | 1094.1 | 967.5 | -11.6% |
| 首内容 P95 ms | 1161.9 | 1063.4 | -8.5% |
| 首内容 P99 ms | 1197.1 | 1126.1 | -5.9% |
| Hub 握手 wall 中位数 ms | 538.4 | 477.4 | -11.3% |
| Hub 握手密钥计划 wall 中位数 ms | 168.3 | 141.9 | -15.7% |
| Hub 应用密钥计划 wall 中位数 ms | 298.9 | 270.4 | -9.5% |
| Provider 握手 wall 中位数 ms | 538.1 | 476.7 | -11.4% |
| 四进程平均 CPU 核数 | 3.89 | 3.65 | 本窗口观察 |
| 同一采样时刻四进程 RSS 合计峰值 MiB | 403.1 | 388.2 | 本窗口观察 |

JSON 首内容是完整 JSON，不是模型首 token。固定计划少 25% 压缩块不等于整条业务路径快 25%。这是单轮对照，顺序、共享宿主调度、缓存和采样开销都可能影响结果，不声称统计显著或跨硬件通用提速。

macOS `sample` 记录所有线程，包括等待线程，且明显影响吞吐；本表不能用作关闭采样后的 SLO。最终构建另一次只有 Go CPU profile 的 60 秒负载完成 468 请求、零失败，完成量约 7.73/秒，首内容 P95 约 579 ms；方法不同，不能拿它与本表计算优化倍率。详见 [持续负载与恢复报告](production-validation-2026-10-27.md)。

分阶段 CPU 是整个进程在该区间的 CPU 增量，可能包含并发任务；父子和重叠阶段不可相加。原生栈仅用于确认热点路径，不换算成独占 CPU 饼图。

## 最终引擎与业务验证

真实两方 MPC、独立 rustls 上游的 release 测试覆盖六档容量，测得：

| 最大请求容量 | 预热 ms | 在线投递 ms |
| --- | ---: | ---: |
| 4 KiB | 79.0 | 1.8 |
| 16 KiB | 71.9 | 2.0 |
| 64 KiB | 73.6 | 2.4 |
| 256 KiB | 96.3 | 8.1 |
| 1 MiB | 74.4 | 13.5 |
| 5 MiB | 72.9 | 59.6 |

这些是独立引擎样本，不包含 Go 路由、上游推理和业务队列，不能与四进程负载混为一谈。错误 DNS、计划不一致及非法凭证字符被拒绝；输出 MAC、记录认证和 HMAC 填充/分片/多消息对照继续通过。最终四进程 TLS 1.2、TLS 1.3 及接近 5 MiB prompt 的 smoke 均通过。

Go 全量 race/vet、Rust workspace、Clippy（warnings 为错误）、rustfmt 和 Python 三项诊断回归通过。额外指定与部署相同的 release sidecar，执行 Go/Rust 进程接口的 integration + race 检查，TLS 1.2 / 1.3 均通过；另显式运行默认忽略的 TLS 1.2 真实 sidecar MPC 测试，通过。故障、持续负载与结算结果单独记录，避免将单元测试当成稳定性验收。

最终构建连续执行 JSON 1 RPS、SSE 1 RPS 和并发 4 饱和负载，各 300 秒，2928 次请求全部成功，2928 份回执与结算对应，pending 为零。饱和阶段稳态约 7.76 请求/秒，首内容 P95 585 ms，四进程采样 RSS 合计峰值 505 MiB。Agent 每分钟 RSS 中位数约 22.5–25.3 MiB，未出现单调持续增长；这不能替代更长运行或独立泄漏分析。逐分钟窗口、故障恢复与账本核对见 [完整报告](production-validation-2026-10-27.md)。

## 公网与指纹证据

探测程序运行真实双方 MPC 引擎，通过公开路径发送无 Authorization GET，不调用付费推理。ClientHello 指纹从实际网络发送前捕获的明文字节计算；跨语言 fixture 与 Rust 生成器逐字节对照，解析器拒绝截断。

最终构建访问 `www.cloudflare.com /cdn-cgi/trace` 两次均完成认证 HTTP 200 和 TLS close_notify，普通 TLS 基线也返回 200。两次实际 ClientHello 的 JA3 为 `fe282bc22b5ca253a3961431d569f58d`，JA4 为 `t13d0106h1_0f2cb44170f4_6dca215ec8fb`。探测没有发送 Authorization，当前 pull relay 不能检测提前响应，`full_request_consumption_confirmed` 保持 false；这是一项公网互操作观察，不是目标 API 的业务准入。

`api.openai.com /v1/models` 的普通 TLS 基线失败；两次 MPC 探测均在 TCP connect 阶段 60 秒超时，没有发送 ClientHello。只能说明本机直连出口无法完成访问，不能据此判断 KeyUpdate、指纹或真实业务兼容性。

真实 Provider 出口、有凭证业务请求、模型与 usage 核对仍需按 [ADR 0004](../adr/0004-upstream-compatibility-validation.md) 执行。公网返回 200/401/403 均不独立证明完整请求消费、账号安全或生产准入。

## 复现与材料

```sh
python3 scripts/profile-warm.py --tls-version 1.3 --seconds 30
python3 scripts/validate-production.py --mode faults
python3 scripts/validate-production.py --mode profile
python3 scripts/validate-production.py --mode soak --seconds 300
python3 scripts/probe-upstream.py --host www.cloudflare.com --path /cdn-cgi/trace --samples 2
python3 -m unittest discover -s scripts -p test_diagnostics.py
```

优化前目录 `/tmp/tokenhive-warm-profile-azsg8hh1`；最终目录 `/tmp/tokenhive-warm-profile-rit87s3k`，两端原生栈均捕获成功。最终公网探测目录 `/tmp/tokenhive-upstream-probe-5x27cd7x`，probe 二进制 SHA 已记录。总验证执行记录见数据中的 `final_validation`。原部署目录包含生成配置与私钥，分享本报告及脱敏 JSON 即可。历史 EPYC 2 CPU 数据保留原日期，不与本轮直接比较。
