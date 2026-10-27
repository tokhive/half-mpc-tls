# ADR 0006：TLS 1.3 使用共享 5 MiB 档位

日期：2026-10-27。状态：已实现默认配置；部署准入仍按实际资源和上游验收。

TLS 1.3 新 sidecar 未指定 `--capacity` 时使用 `5m`，demo 的显式 TLS 1.3 模式采用相同默认值；TLS 1.2 默认 baseline 保持不变。Go route 必须显式选择 TLS 1.3 并匹配精确 `5m` capacity，示例见 [配置](../../config/hub-tls13.example.json)。双方必须匹配，不静默扩大用户配置的上限。

当前 [WarmPrefix](../../rust/crates/tls13/src/record.rs)只为最多 1 KiB 凭证前缀及 KeyUpdate 准备 AES，后续请求正文在下一代密钥下本地处理。因此没必要仅因请求预算不同部署六组 TLS 1.3 sidecar 和预热池。一个 `5m` 进程/池同时处理所有更小请求；这是现有容量和协议形状的复用，不改变电路或密钥释放流程。

显式 `--capacity baseline|16k|64k|256k|1m|5m` 继续支持，便于原部署保持配置和资源限制。新默认不会让未显式升级的 TLS 1.2 route 选中 TLS 1.3，也不会改变当前最大 5 MiB 请求与 16 MiB 响应的上限。预热基本不随 TLS 1.3 正文预算增长，不意味着在线内存、正文传输、请求解析或5 MiB并发资源成本为零。

不同请求容量以外的 Provider、credential、host/port/SNI 和 TLS 版本仍隔离库存。跨身份或秘密配对合池不属于此决策。TLS 1.2 的 AES 预求值仍与预算相关，继续使用六档；[一次性约束](0002-precomputation-and-one-shot-sessions.md)同样保留。
