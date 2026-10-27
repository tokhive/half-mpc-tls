# ADR 0001：可信 Hub 与方向性密钥释放

日期：2026-10-27。状态：已接受，用户明确确认。

当前信任 Hub 遵守协议、验证真实上游并正确结算；Provider 可以恶意；上游 API 和证书信任链可信。Provider 凭证保持本地私有输入，Consumer 不独立验证 TLS。抵抗主动恶意或被攻陷的 Hub 不在本轮范围内。

接受 TLS 1.3 Hub 作为 garbler、对输出进行认证、取得旧记录 H/tag mask 与 KeyUpdate 后的下一代客户端 secret。暂不将完整 tag 移入 MPC，也不为恶意 Hub 引入双重执行。TLS 1.2 继续现有方向性服务器密钥释放与客户端秘密共享路径。

该决策不删除 nonce/sequence 唯一性、一次性状态、证书/DNS/Finished、输出认证、规范请求绑定、投递 ACK 或结算证据检查。协议实现错误及恶意 Provider 仍必须失败关闭。两种引擎的秘密归属和调用接口见 [当前架构](../current-architecture.md)。若未来扩大 Hub 威胁模型，须重新审查完整 KE/HKDF/电路/输入/记录/密钥释放链路，不能通过单个模板检查宣称完成升级。
