# Half-MPC TLS 设计评审与优化结果

2026-10-27。安全前提由用户确认：**可信 Hub、可恶意 Provider**。

整体分层和选择性 MPC 方向合理。当前最值得优先处理的是恢复与资源生命周期的正确性，以及每个请求都要承担的 MPC 预热成本。本轮已实现这些修复、完成库存与传输方案评估，并将当前架构从历史设计中分离。实测数据见 [优化报告](performance/optimization-2026-10-27.md) 和 [持续负载与恢复验证](performance/production-validation-2026-10-27.md)。

## 安全模型与必须保留的边界

Hub 遵守协议，正确执行规范请求校验、上游身份与响应认证、路由及结算；Consumer 信任 Hub，不独立验证 TLS 证据。Provider 可以恶意，上游 API 与证书信任链可信。Provider 凭证仍留在本地，作为 MPC 私有输入，凭证隐私以 Hub 遵守协议为前提。主动恶意或已被攻陷的 Hub 不属于当前范围。

TLS 1.3 的公开前缀由 Hub 输入，旧记录的 GHASH 子密钥及 tag mask 交给 Hub 计算 tag，是这个模型下接受的取舍。不能据此宣称抵抗恶意 Hub；未来扩大模型需重审输入一致性、混淆电路、密钥释放和上游行为，不能仅增加普通模板校验。

nonce/sequence 唯一性、一次性材料消费、请求/模型/哈希绑定、证书和 Finished 校验、MPC 输出认证、容量限制及投递 ACK 继续由实现强制保证。信任 Hub 不等于忽略实现错误。详见 [当前架构](current-architecture.md) 和 [ADR 0001](adr/0001-trusted-hub-and-directional-keys.md)。

## 已完成的正确性修复

| 问题 | 当前行为 | 验证 |
| --- | --- | --- |
| 超预算认证回执会阻塞恢复，或在重启时错误退款 | 进入持久化 `review_required`，保留原预留及不可变回执；其他合法回执继续恢复 | 覆盖仅回执落盘、review 也落盘、重复重启、存储失败、证据冲突及幂等性 |
| Provider 连接退出留下 watcher，未完成拨号可越过清理边界 | 每次 Serve 独立取消域；退出时取消并等待拨号，再关闭全部连接 | watcher 数量、控制断开取消、pending dial 竞态回归 |
| 响应 deadline 与健康错误归因竞态 | 传输关闭与归因共用响应 context；Consumer 断开仍排空至原期限 | deadline 回归连续 100 次；超预算不返回成功 JSON、不误罚 Provider |

`review_required` 不自动扣费、退款或分账，也不视为成功任务。没有在缺少业务政策的情况下增加调账接口；当前状态和限制已写入接入文档。

## 性能与架构决定

1. **先测量再减少密钥计划的重复工作。** 增加分阶段 wall/进程 CPU 计时与原生栈采样。TLS 1.3 的密钥计划明显比 ECDHE 份额阶段昂贵，因而优先复用同一 VM、同一密钥的 HMAC pad 压缩状态。固定计划 SHA-256 压缩块由 40 降至 30；不复用 OT、随机性、nonce 或已消费记录。单轮带采样负载稳态由 3.55 到 4.10 请求/秒，P95 首内容由 1162 到 1063 ms。方法与限制见优化报告。
2. **TLS 1.3 新部署共享一个 5 MiB 档位。** 未指定容量时，显式 TLS 1.3 使用 `5m`；TLS 1.2 仍默认 `baseline`。保留显式旧容量及精确协商，不自动重写已有多 route 配置。固定凭证前缀仍最多 1 KiB，小请求不会扩大 MPC 凭证电路。见 [ADR 0006](adr/0006-shared-tls13-capacity.md)。
3. **保留一次性会话，不立即增加两层库存。** 离线预处理依赖两方交互、活跃 VM、角色和执行顺序；不是可无限保存、任意复制的无状态材料。两层库存会新增状态、内存和清理成本。TLS 1.2 多请求复用还需要改造记录/请求绑定和账务生命周期，不能只提高 `MaxUses`。见 [ADR 0002](adr/0002-precomputation-and-one-shot-sessions.md)。
4. **保留独占 mTLS generation 槽位。** 它隔离会话拥塞与清理生命周期；默认 32 槽限制 warming、READY 和 leased 合计。当前证据不足以证明 QUIC 值得其迁移成本；包级 ACK 也不能替代上游 socket 写入 ACK。见 [ADR 0003](adr/0003-session-transport-isolation.md)。
5. **用实际能力和 MPC 时序判断兼容。** 原评审“必须精确构建版本一致”不准确，当前是 v1、严格 JSON、角色、必需 feature 和容量协商。本次 HMAC 改动增加必需 feature 及 `InitV2` schedule revision 2，真实 Bincode 混版本测试在凭证贡献与 ClientHello 之前拒绝错误时序。没有实现 v2，暂不添加虚假的版本区间。见 [ADR 0005](adr/0005-protocol-compatibility.md) 和 [0007](adr/0007-session-local-hmac-prefix-states.md)。

TLS 1.2 继续作为兼容默认；TLS 1.3 显式启用且不自动降级。真实上游准入通过之后，再决定是否改变默认。

## 文档与验证结果

- README 已改为当前入口；里程碑内容归档至 [实现历史](implementation-history.md)。新增当前架构、七份 ADR、profiling 方法，并同步业务接入及 RPC 能力约束。
- 原始中英文协议文档标为历史设计，明确可信 Hub 前提；连接复用、性能和密钥释放以当前实现文档为准。
- Go 全量 race、vet，期限与连接专项重复测试，Rust workspace、Clippy、rustfmt 均通过；真实两方 TLS 1.3 六档容量、错误 DNS/计划及输出认证回归通过。
- 最终构建执行 TLS 1.2 / 1.3 四进程 smoke、接近 5 MiB prompt、SDK JSON/SSE、故障恢复、CPU profile 和持续负载，详细结果及构建 SHA 记录在报告中。
- 公网探测使用真实 MPC 引擎和无 Authorization 请求；ClientHello 从实际发送字节提取，避免用系统 TLS 的指纹冒充本引擎。普通 TLS 基线和本引擎访问 `api.openai.com` 都未能建立直连，不能将其解释为 KeyUpdate 不兼容。公网可达性与业务准入分层处理，见 [ADR 0004](adr/0004-upstream-compatibility-validation.md)。

## 仍需部署环境回答的问题

当前证据不覆盖真实 Provider 出口、真实凭证/模型/usage、跨机带宽与丢包或 24 小时稳定性。历史少量样本中的握手超时也不能因本轮通过而宣称已根治。指纹可测量，但没有证据可由 JA3/JA4 推断账号封禁概率。

多 Hub 共写日志、待核对任务的账务解决政策、两层预处理和多请求会话均有明确边界，未通过放宽状态机来隐式启用。当前规划中的实现、评估与本机验证已完成；部署准入仍需对应环境证据。
