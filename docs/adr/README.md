# 架构决策

| ADR | 当前决定 |
| --- | --- |
| [0001 可信 Hub](0001-trusted-hub-and-directional-keys.md) | 保留方向性密钥释放与恶意 Provider 防护 |
| [0002 预处理与一次性会话](0002-precomputation-and-one-shot-sessions.md) | 保留一次性；两层库存需阶段 profile 和空闲损耗证据 |
| [0003 传输隔离](0003-session-transport-isolation.md) | 保留独占 mTLS 槽位，暂不改 QUIC |
| [0004 真实上游验收](0004-upstream-compatibility-validation.md) | 分开本地、无凭证公网和有凭证业务准入 |
| [0005 协议兼容](0005-protocol-compatibility.md) | 当前保留 v1 + 必需特性，不虚构未实现的版本区间 |
| [0006 TLS 1.3 容量](0006-shared-tls13-capacity.md) | 新部署共享单个 5 MiB 档位，保留显式旧档位 |
| [0007 单会话 HMAC 前缀状态](0007-session-local-hmac-prefix-states.md) | 减少重复电路求值，显式拒绝新旧 MPC 时序混用 |
