# Half-MPC TLS 设计评审

2026-10-27

结论：方向合理，工程质量高于一般 MVP；但 TLS 1.3 路径下 Hub 只需改动自身输入即可获取 Provider 的 API key，需优先修复。其次是设计文档与实现严重脱节，以及吞吐受限于每请求一次的 MPC 预热。

## P0 安全

### 1. TLS 1.3 凭证前缀：公开字节由 Hub 决定，tag 也由 Hub 计算

Hub 只需改动自己的输入或事后改写记录，就能让上游把凭证回显出来，再用 server key 解密拿到。不需要构造恶意混淆电路。

代码依据：

- `rust/crates/tls13/src/record.rs:208-216`：前缀中除凭证外的字节只来自 Hub 的电路输入 `a`。Provider 本地校验的模板没有在电路内与 `a` 绑定。
- `record.rs:253-256`：GHASH 子密钥 `h` 和两个 tag mask 作为私有输出交给 Hub，由 Hub 调用 `finish_record` 组装记录。

两条攻击路径：

1. **改输入**：Hub 输入别的前缀，例如 `GET /` + [凭证]。凭证字符集限制为 0x21–0x7e，正好是合法的 URL 路径字符。
2. **事后改写**：Hub 知道公开位置的明文，也就知道对应 keystream，可任意改写公开字节，再用 H 和 mask 重算 tag。

上游对未知路径的常见报错会回显路径（如 `Invalid URL (GET /sk-...)`）。Hub 持有 server key，解密响应即得凭证。

修复方向：

- 凭证前的前缀固定为每条 route 的常量（`POST /v1/... Host: ... Authorization: Bearer `），作为双方都知道的公开值，或改由 Provider 输入；不能只由 Hub 输入。
- tag 在 MPC 内算完，完整密文和 tag 一起输出，由 Provider 原样写给上游。Hub 不再拿到 `h` 和 mask。KeyUpdate 记录同样处理。
- 补负面测试：Hub 输入与模板不符、Hub 改写密文后 tag 失败，两种情况都不能有字节到达上游。

### 2. 信任模型与产品承诺不一致

文档写明凭证隐私只抵抗半诚实 Hub（`tls12-selective-mpc-implementation-zh.md:23-25`、`rust/crates/tls13/README.md:20`）。对 Provider 而言，这等于"信任 Hub 运行的是诚实代码"，而这恰恰是他们无法验证的。

TLS 1.3 模块由 Hub 生成混淆电路且不使用 DEAP。恶意的电路生成方可以直接生成输出凭证的电路。

凭证电路很小（前缀 ≤1024 字节外加 KeyUpdate），升级到抗恶意方案的成本可控：可对这一段改用双重执行（TLS 1.2 已 vendor 了 `tlsn-deap`），或采用认证混淆。升级前，对外表述应如实标注为"半诚实"。

### 3. TLS 1.2 待核实

TLS 1.2 的 GHASH 密钥 H 是秘密共享的（`rust/vendor/tlsn-mpc-tls/src/record_layer/aead/ghash.rs`），事后改写这条路走不通。但 Hub 提供的模板字节是否在电路内受 Provider 约束，本次评审**尚未确认**，需按同一问题再审一遍。

## P1 设计文档与实现脱节

`half-mpc-tls-binding-zh.md`（v2.0）在多个关键点上已不成立，其中一处描述本身就是 P0 的危险模式。

| 文档描述 | 实际实现 / 实测 |
| --- | --- |
| §6.4 步骤 3：H 和 J0 "仅给 Hub" | 正是 P0 的危险模式；TLS 1.2 实现反而正确地秘密共享 |
| 连接复用，每 100 个请求做一次 KeyUpdate | `MaxUses: 1`，一会话一请求；KeyUpdate 用于把正文交给 Hub 本地加密 |
| 握手 2–5 s，每请求约 2 ms | 握手约 0.42–0.62 s；TLS 1.2 请求在线 12–55 ms，随大小线性增长 |
| 以 TLS 1.3 为主线 | 默认 TLS 1.2，TLS 1.3 需显式选择 |

建议把 README 中的变更日志迁出，改为一份"当前架构 + 信任边界"文档，加上若干 ADR（架构决策记录）。主设计文档应标注为历史版本或按实现重写。

## P1 性能与架构

吞吐上限由预热决定，不在在线路径：四进程压测在并发 1/4/8 下稳态都约 1.37 req/s（2 vCPU），因为每个请求都要做一次完整 MPC 握手。

1. **先做分阶段 CPU profile。** OT、ECDHE、PRF/HKDF、garbling 各占多少目前没有数据（`docs/performance/e2e-2026-10-26.md` 自己也承认）。没有它，后续优化都是猜测。
2. **库存分两层。** 不依赖输入的预处理（OT、garbling）不连上游、不会过期，可以多囤；已建立 TLS 连接并完成握手的会话按需少量保持。`MaxIdle` 现为 2 分钟，可能长于真实上游的空闲断连时间，会浪费预热。分层还能减少 Provider 到上游的长连接数。
3. **TLS 1.3 合并容量档位。** 实测 4 KiB 到 5 MiB 的预热都在 416–454 ms，与容量基本无关（正文由 Hub 本地加密）。6 个档位、每档一个 sidecar 进程在 TLS 1.3 下是多余的；合成一档后配置更简单，库存不再分散到 6 个池，命中率更高。
4. **上游支持时默认用 TLS 1.3。** 4 KiB 请求在线 4.7 ms，TLS 1.2 约 55 ms。TLS 1.2 保留并按 route 显式选择，可考虑一个会话承载多个请求（`MaxUses>1`）来分摊握手。TLS 1.3 把新一代客户端密钥交给了 Hub，结构上只能一会话一请求。
5. **每会话独占一条物理连接，默认 32 条。** 在 SSE 长流加一次性会话的情况下，这实际限制了单个 Provider 的并发。后续可考虑带逐流流控的多路复用（例如 QUIC）。

## P2 兼容性与运维风险

- **客户端 KeyUpdate 未在真实上游验证。** 目前只测过本地 OpenSSL 和 rustls；真实上游（如前置 Cloudflare 的 OpenAI）能否在请求中途接受客户端 KeyUpdate，需要实测。
- **ClientHello 指纹少见。** 只有 P-256 和一个密码套件，JA3/JA4 指纹特殊，可能被上游风控标记，削弱"保留 Provider IP、避免封号"的目标。
- **偶发握手卡死未解决。** 12 个样本中 1 次握手超时，根因在 TLSNotary/MPZ（`benchmark-results.md`）。
- **四个组件必须同步升级。** Hub、Agent、两个 sidecar 只接受完全一致的版本；建议改为协商版本区间，否则难以灰度。
- **压测仅限单机 2 vCPU。** 跨机网络、真实上游、长时间稳定性均未验证。

## 下一步

- [ ] P0：TLS 1.3 前缀改为常量或由 Provider 输入，tag 在 MPC 内输出、由 Provider 原样转发，补负面测试
- [ ] P0：按同一问题审查 TLS 1.2 路径的模板绑定
- [ ] P0：确定凭证电路升级到抗恶意安全的方案；升级前修正对外的安全表述
- [ ] P1：重写或归档主设计文档，补当前架构说明与 ADR
- [ ] P1：对预热做分阶段 CPU profile
- [ ] P1：评估两层库存、TLS 1.3 单档位、TLS 1.2 多请求会话
- [ ] P2：真实上游的 KeyUpdate 与 ClientHello 指纹探测
- [ ] P2：组件版本改为区间协商
