# Half-MPC TLS 绑定：无需可信硬件的可验证 LLM API 中继协议

> 一种协议，用于证明 LLM API 中继节点（Provider）确实将请求转发给了声称的上游 API（如 OpenAI），并返回了真实的响应——无需 TEE 硬件，也不会暴露 Provider 的 API 密钥。

## 目录

- [1. 概述](#1-概述)
- [2. 问题陈述](#2-问题陈述)
- [3. 威胁模型](#3-威胁模型)
- [4. 背景知识：TLS 1.3](#4-背景知识tls-13)
  - [4.1 TLS 为什么存在](#41-tls-为什么存在)
  - [4.2 对称加密与非对称加密](#42-对称加密与非对称加密)
  - [4.3 TLS 握手：桥接非对称与对称](#43-tls-握手桥接非对称与对称)
  - [4.4 TLS 1.3 完整握手流程](#44-tls-13-完整握手流程)
  - [4.5 密钥派生：从共享密钥到流量密钥](#45-密钥派生从共享密钥到流量密钥)
  - [4.6 AES-GCM 记录加密](#46-aes-gcm-记录加密)
  - [4.7 HTTP Keep-Alive：一次握手，多个请求](#47-http-keep-alive一次握手多个请求)
  - [4.8 TLS 密钥更新](#48-tls-密钥更新)
  - [4.9 为什么 TLS 无法向第三方证明数据来源](#49-为什么-tls-无法向第三方证明数据来源)
- [5. 背景知识：多方安全计算（MPC）](#5-背景知识多方安全计算mpc)
  - [5.1 MPC 做了什么](#51-mpc-做了什么)
  - [5.2 混淆电路](#52-混淆电路)
  - [5.3 不经意传输（OT）](#53-不经意传输ot)
  - [5.4 离线/在线分离](#54-离线在线分离)
- [6. 协议设计](#6-协议设计)
  - [6.1 角色定义](#61-角色定义)
  - [6.2 Phase 0：MPC-TLS 握手（一次性）](#62-phase-0mpc-tls-握手一次性)
  - [6.3 Phase 1：非对称密钥分配](#63-phase-1非对称密钥分配)
  - [6.4 Phase 2：请求加密（每次请求）](#64-phase-2请求加密每次请求)
  - [6.5 Phase 3：响应解密（每次请求）](#65-phase-3响应解密每次请求)
  - [6.6 Phase 4：验证与结算](#66-phase-4验证与结算)
- [7. 为什么叫 "Half-MPC"](#7-为什么叫-half-mpc)
- [8. 安全性分析](#8-安全性分析)
- [9. 性能分析](#9-性能分析)
- [10. 连接池与生命周期管理](#10-连接池与生命周期管理)
- [11. 与替代方案的对比](#11-与替代方案的对比)
- [12. 实现建议](#12-实现建议)
- [13. 局限性与未来工作](#13-局限性与未来工作)

---

## 1. 概述

本文描述了一种 **Half-MPC TLS 绑定**协议，专为 LLM API 配额共享平台设计。在这类平台中，**Provider**（提供者）将其 LLM API 访问权限（如 OpenAI API 密钥或 Codex OAuth 令牌）通过一个中央 **Hub**（调度中心）共享给 **Consumer**（消费者）。核心挑战在于验证 Provider 确实将请求转发给了声称的上游 API 并返回了真实响应，而不是偷偷替换了更便宜的模型或篡改了输出。

"Half-MPC"（半 MPC）这个名称反映了关键的架构洞察：**MPC（多方安全计算）仅用于请求加密（客户端→服务端方向），而响应解密（服务端→客户端方向）由 Hub 独立完成。** 这种非对称设计以极小的性能开销提供了强验证保证。

### 核心特性

| 特性 | 保证 |
|---|---|
| **响应真实性** | Hub 可以独立验证响应确实来自上游 API（如 api.openai.com） |
| **API 密钥隐私** | Hub 永远不会知道 Provider 的 API 密钥 |
| **IP 地址保留** | 上游 API 看到的是 Provider 的 IP 地址，而非 Hub 的 |
| **无需特殊硬件** | 任一方都不需要 TEE（Intel TDX、AWS Nitro 等） |
| **低延迟开销** | 每次请求约 2ms 的 MPC 加密开销；响应解密 0ms 开销 |

---

## 2. 问题陈述

考虑以下 LLM API 配额共享架构：

```
Consumer ──请求──> Hub ──任务──> Provider ──API 调用──> api.openai.com
Consumer <──响应── Hub <──结果── Provider <──响应────── api.openai.com
```

Provider 持有上游 API 的密钥（或 OAuth 令牌）。Hub 将 Consumer 的请求分配给可用的 Provider。信任问题是：

> **Hub 如何验证 Provider 确实用 Consumer 的 prompt 调用了 `api.openai.com`，并返回了真实的响应——而不是替换了更便宜的模型、修改了 prompt，或者篡改了输出？**

### 现有方案及其局限性

| 方案 | 工作原理 | 局限性 |
|---|---|---|
| **自签名收据**（如 AntSeed ResponseAuth） | Provider 对其返回的响应签名哈希 | Provider 可以先篡改再签名 |
| **TEE 远程证明**（如 Intel TDX） | 在硬件安全飞地中运行中继程序并进行远程证明 | 需要专用服务器硬件（第 4 代+ Xeon）；成本高、运维复杂 |
| **完整 MPC-TLS**（如 TLSNotary） | Hub 和 Provider 通过多方安全计算联合操作 TLS 连接 | 请求和响应都经过 MPC——延迟高（每请求数秒级），尤其不适合 LLM 流式输出 |
| **代理模式**（Hub 作为 TCP/TLS 代理） | Hub 建立 TLS 连接，通过 Provider 的 TCP socket 转发流量 | 上游 API 看到 Hub 的 IP；或多个 Provider 密钥从同一 Hub IP 发出，触发封号 |

Half-MPC TLS 绑定同时解决了以上四个局限性。

---

## 3. 威胁模型

### 可信方

- **Hub**：由平台运营。被信任不会向 Consumer 伪造虚假响应（其声誉依赖于响应质量）。可能对 Provider 的 API 密钥感到好奇。
- **上游 API**（如 OpenAI）：被信任对合法请求返回诚实的响应。

### 不可信方

- **Provider**：可能尝试：
  - 替换更便宜的模型（如用量化的开源模型代替 GPT-4o）
  - 在转发前修改 Consumer 的 prompt
  - 篡改上游 API 的响应
  - 声称调用了 OpenAI 但实际调用了其他更便宜的服务

### 需保护的资产

| 资产 | 保护目标 |
|---|---|
| Provider 的 API 密钥 | Hub 不能获知 |
| Consumer 的 prompt | Provider 会看到（推理中继的固有特性；prompt 隐私需要额外的 Hub 侧 TEE） |
| 响应完整性 | Hub 必须能验证响应是真实且未被修改的 |
| Provider 的 IP 身份 | 上游 API 必须看到 Provider 的 IP，而非 Hub 的，以避免封号 |

---

## 4. 背景知识：TLS 1.3

本节详细介绍 TLS 1.3——保护 HTTPS 连接安全的加密协议。理解 TLS 内部机制是必要的，因为 Half-MPC 协议的工作原理就是将 TLS 操作分拆到两方之间。

### 4.1 TLS 为什么存在

当你的浏览器（或 API 客户端）连接到 `api.openai.com` 时，数据会经过许多中间路由器、ISP 和网络设备。没有加密的话，这些中间方可以：

- **读取**数据（窃听）：看到你的 API 密钥、prompt、模型的响应
- **修改**数据（篡改）：改变你的 prompt、修改响应、注入内容
- **冒充**服务器（欺骗）：假装是 `api.openai.com` 并返回虚假响应

TLS（传输层安全协议）通过在客户端和服务端之间建立加密、认证的通道来防止以上三种攻击。TLS 1.3（RFC 8446，2018 年发布）是当前版本，比 TLS 1.2 显著更简洁、更快速。

### 4.2 对称加密与非对称加密

TLS 使用两种密码学方法，各有独特优势：

**对称加密**（如 AES-GCM）：
- 一个共享密钥用于加密和解密
- 极快（现代 CPU 配合 AES-NI 可达约 10 GB/s）
- 问题：两个从未见过面的人如何就共享密钥达成一致？

```
Alice ──AES(key, "hello")──> 密文 ──AES(key, 密文)──> Bob 看到 "hello"
                                    （两端使用相同密钥）
```

**非对称加密**（如 ECDH、RSA）：
- 两个数学相关的密钥：公钥（公开分享）和私钥（保密持有）
- 任何人都可以用公钥加密；只有私钥持有者可以解密
- 比对称加密慢得多（约 1000 倍）
- 用于两个目的：
  - **密钥交换**：通过不安全的通道协商共享密钥（ECDH）
  - **数字签名**：证明身份（证书上的 RSA/ECDSA 签名）

```
Server 发布：public_key
Alice 计算：shared_secret = ECDH(alice_private, server_public)
Server 计算：shared_secret = ECDH(server_private, alice_public)
             （双方得到相同的密钥，但窃听者无法计算出来）
```

**TLS 结合了两者**：使用非对称加密一次（慢，但不需要预共享密钥）来建立对称密钥，然后使用对称加密（快）处理所有实际数据。

### 4.3 TLS 握手：桥接非对称与对称

TLS 握手是 TLS 连接的初始阶段。其任务是：

1. **验证服务端身份**：确认你正在与真正的 `api.openai.com` 通信（通过证书链）
2. **协商密码套件**：就使用哪些算法达成一致（如 `TLS_AES_128_GCM_SHA256`）
3. **建立共享密钥**：使用 ECDH 密钥交换派生对称会话密钥
4. **派生流量密钥**：将共享密钥通过密钥派生函数生成实际的加密密钥

握手完成后，双方拥有相同的对称密钥，后续所有数据都使用 AES-GCM（或 ChaCha20-Poly1305）加密。

### 4.4 TLS 1.3 完整握手流程

TLS 1.3 在一个往返（1-RTT）中完成握手：

```
Client（如 Provider）                         Server（如 api.openai.com）
          |                                               |
  步骤 1  |── ClientHello ───────────────────────────────>|
          |   • 支持的密码套件列表                          |
          |   • 支持的椭圆曲线                              |
          |   • key_share: g^a（ECDH 公钥）                |
          |   • random（32 字节随机数）                     |
          |                                               |
  步骤 2  |<─ ServerHello ────────────────────────────────|
          |   • 选定的密码套件                              |
          |   • key_share: g^b（ECDH 公钥）                |
          |   • random（32 字节随机数）                     |
          |                                               |
          |   ─── 以下内容全部加密传输 ───                  |
          |       （使用握手阶段的流量密钥）                  |
          |                                               |
  步骤 3  |<─ {EncryptedExtensions} ──────────────────────|
          |   • 服务端参数                                  |
          |                                               |
  步骤 4  |<─ {Certificate} ──────────────────────────────|
          |   • 服务端的 X.509 证书链                       |
          |   （证明这是 api.openai.com）                   |
          |                                               |
  步骤 5  |<─ {CertificateVerify} ────────────────────────|
          |   • 对握手记录的签名                             |
          |   （证明服务端持有与证书匹配的私钥）               |
          |                                               |
  步骤 6  |<─ {Finished} ────────────────────────────────|
          |   • 对整个握手记录的 MAC                         |
          |   （确认握手未被篡改）                           |
          |                                               |
  步骤 7  |── {Finished} ───────────────────────────────>|
          |   • 客户端的握手记录 MAC                         |
          |                                               |
          ════════ 握手完成 ════════════════════════════
          |                                               |
  步骤 8  |── {Application Data} ───────────────────────>|
          |   • 如：HTTP POST /v1/chat/completions         |
          |<─ {Application Data} ─────────────────────────|
          |   • 如：HTTP 200 OK + SSE 流                   |
```

**各步骤详解：**

- **步骤 1（ClientHello）**：客户端提出加密参数并发送其 ECDH 公钥 `g^a`（其中 `a` 是客户端生成的随机私有值）。

- **步骤 2（ServerHello）**：服务端选择密码套件并发送其 ECDH 公钥 `g^b`。此时双方都可以计算 ECDH 共享密钥：`shared_secret = g^(a·b)`。客户端计算 `(g^b)^a`，服务端计算 `(g^a)^b`——结果相同，但窃听者只看到 `g^a` 和 `g^b` 而无法计算 `g^(a·b)`（这是椭圆曲线 Diffie-Hellman 假设）。

- **步骤 3-6**：服务端发送其证书链、一个证明其持有证书私钥的签名，以及一个确认握手未被篡改的 MAC。这些消息已经使用从 ECDH 共享密钥派生的密钥加密。

- **步骤 7**：客户端发送自己的 Finished 消息，确认握手从客户端侧完成。

- **步骤 8+**：应用数据（HTTP 请求和响应）开始流动，使用从共享密钥派生的应用流量密钥加密。

### 4.5 密钥派生：从共享密钥到流量密钥

ECDH 共享密钥不会直接用作加密密钥。相反，它被输入 **HKDF（基于 HMAC 的密钥派生函数）** 密钥调度器，派生出多个独立的密钥：

```
                    ECDH 共享密钥：g^(a·b)
                              |
                    ┌─────────┴──────────┐
                    │   HKDF-Extract     │
                    │   (salt=0, ikm=0)  │
                    └─────────┬──────────┘
                              |
                         Early Secret
                              |
                    ┌─────────┴──────────┐
                    │   HKDF-Extract     │
                    │  (ES, shared_sec)  │
                    └─────────┬──────────┘
                              |
                       Handshake Secret
                              |
              ┌───────────────┼───────────────┐
              |                               |
    HKDF-Expand-Label             HKDF-Expand-Label
    "c hs traffic"                "s hs traffic"
              |                               |
  client_handshake_               server_handshake_
  traffic_secret                  traffic_secret
  （加密客户端握手消息）             （加密服务端握手消息）
                              |
                    ┌─────────┴──────────┐
                    │   HKDF-Extract     │
                    │   (HS, 0)          │
                    └─────────┬──────────┘
                              |
                        Master Secret
                              |
              ┌───────────────┼───────────────┐
              |                               |
    HKDF-Expand-Label             HKDF-Expand-Label
    "c ap traffic"                "s ap traffic"
              |                               |
  client_application_             server_application_
  traffic_secret                  traffic_secret
              |                               |
     ┌────────┴────────┐            ┌────────┴────────┐
     |                 |            |                 |
  client_           client_      server_           server_
  write_key         write_iv     write_key         write_iv
  (AES 密钥)        (GCM IV)     (AES 密钥)        (GCM IV)
```

**Half-MPC 的关键属性**：客户端和服务端的应用流量密钥是通过**独立的 HKDF-Expand-Label 调用**从同一个 Master Secret 派生的。它们是密码学上独立的：知道一个不会泄露另一个。这使得我们可以将 server traffic secret 交给 Hub，同时保持 client traffic secret 在两方之间分享。

每个 traffic secret 进一步扩展为：
- **write key**（16 或 32 字节）：用于加密/解密的 AES 密钥
- **write IV**（12 字节）：用于 AES-GCM nonce 构造的初始化向量

### 4.6 AES-GCM 记录加密

TLS 1.3 中的每条应用数据都作为 **TLS record** 使用 AES-GCM（带关联数据的认证加密）进行加密。AES-GCM 结合了两个操作：

#### AES-CTR（计数器模式）—— 保密性

AES-CTR 通过加密连续的计数器值生成**密钥流**，然后将密钥流与明文异或：

```
对于包含 N 个 block 的明文（每个 block = 16 字节）：

  counter_block[0] = nonce ∥ 0x00000002     （数据的计数器从 2 开始）
  counter_block[1] = nonce ∥ 0x00000003
  ...
  counter_block[i] = nonce ∥ (i + 2)

  keystream[i]  = AES(key, counter_block[i])     ← AES 块加密
  ciphertext[i] = plaintext[i] ⊕ keystream[i]    ← 简单异或
```

其中：
- `key` = write key（从 traffic secret 派生）
- `nonce` = `write_iv ⊕ sequence_number`（12 字节；sequence_number 每条记录递增，从 0 开始）

**重要特性**：每个 16 字节的 block 是独立加密的。block `i` 的加密仅取决于 `key`、`nonce` 和 `i`——不依赖于其他任何 block 的明文。这个特性使得分段 MPC 方法成为可能，即不同的 block 可以用不同方式处理。

#### GHASH —— 认证

GHASH 在有限域 GF(2^128) 上对密文和 AAD（附加认证数据）计算多项式哈希：

```
H = AES(key, 0^128)                              ← 哈希子密钥

GHASH(H, A, C):
  result = 0
  对 A（AAD）中的每个 128 位 block a_i：
    result = (result ⊕ a_i) · H                  ← 在 GF(2^128) 中乘法
  对 C（密文）中的每个 128 位 block c_i：
    result = (result ⊕ c_i) · H
  result = (result ⊕ len(A)∥len(C)) · H
  return result
```

最终的**认证标签**为：

```
tag = GHASH(H, AAD, ciphertext) ⊕ AES(key, nonce ∥ 0x00000001)
```

tag 附加在密文之后（16 字节）。接收方重新计算 tag 并验证是否匹配。如果密文或 AAD 的任何一位被修改，tag 将不匹配（以压倒性概率），该记录将被拒绝。

#### 完整的 TLS Record 结构

```
┌──────────────┬─────────────────────────────────────────────┬─────────┐
│ 记录头        │               加密的有效载荷                  │   Tag   │
│  （5 字节）   │                                             │（16字节）│
│              │  ciphertext[0] | ciphertext[1] | ... | 0x17 │         │
│  type=0x17   │                                             │         │
│  ver=0x0303  │  （明文 = HTTP 数据 + content_type 字节）     │         │
│  length      │                                             │         │
└──────────────┴─────────────────────────────────────────────┴─────────┘
                               |
                        用作 GHASH 的 AAD
                       （= 记录头字节）
```

明文末尾的 `0x17` 字节是**真正的内容类型**（application data = 23 = 0x17）。外层记录头无论实际内容如何，始终显示 `0x17` 和 `0x0303`，这是为了向后兼容。

### 4.7 HTTP Keep-Alive：一次握手，多个请求

HTTP/1.1 默认使用持久连接（`Connection: keep-alive`）。这意味着单个 TCP + TLS 连接可以承载多次 HTTP 请求/响应：

```
┌──────────────── 一个 TLS 会话（一次握手）────────────────┐
│                                                          │
│  请求 1：POST /v1/chat/completions    →  200 OK (SSE)    │
│  （TLS records #0-#3）                  （TLS records #4-#50）│
│                                                          │
│  请求 2：POST /v1/chat/completions    →  200 OK (SSE)    │
│  （TLS records #51-#54）                （TLS records #55-#120）│
│                                                          │
│  ...                                                     │
│                                                          │
│  请求 N：POST /v1/chat/completions    →  200 OK (SSE)    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

TLS **序列号**（用于构造 nonce）在会话中所有记录之间单调递增。它从 0 开始，永远不会重置（直到 Key Update，此时使用新密钥并重置为 0）。

这对 Half-MPC 协议的意义重大：**昂贵的 MPC-TLS 握手只做一次，连接上所有后续请求都使用相同的共享密钥材料。**

### 4.8 TLS 密钥更新

任一方都可以在会话期间触发 **Key Update**（TLS 1.3, §4.6.3）。这会从当前 traffic secret 派生出新的 traffic secret：

```
new_traffic_secret = HKDF-Expand-Label(
    current_traffic_secret,
    "traffic upd",
    "",
    Hash.length                    // SHA-256 为 32 字节
)
```

Key Update 之后：
- 从新的 traffic secret 派生新的 write key 和 IV
- 序列号重置为 0
- 旧密钥被丢弃

Key Update **不需要**新的握手。它是一个轻量级操作（一次 HMAC 调用）。

在 Half-MPC 上下文中：
- **Client traffic secret 的 Key Update**：Hub 和 Provider 必须联合计算新密钥（轻量级 2PC-HMAC，约 1ms）
- **Server traffic secret 的 Key Update**：Hub 持有完整密钥，本地派生新密钥即可（零 MPC 开销）

### 4.9 为什么 TLS 无法向第三方证明数据来源

这是 Half-MPC 协议解决的根本问题。考虑以下情况：

1. Provider（TLS 客户端）连接到 `api.openai.com`（TLS 服务端）
2. TLS 使用**对称密钥**认证（AES-GCM MAC）
3. 客户端和服务端共享**同一个密钥**
4. 因此，客户端可以为**任何**数据计算有效的认证标签——不仅仅是服务端实际发送的数据

如果 Provider 给你一条带有效 tag 的 TLS 记录，你无法分辨：
- (a) 服务端确实发送了该数据（真实的），还是
- (b) Provider 自己伪造了数据并计算了 tag（伪造的）

两者会产生完全相同的、有效的密文 + tag 对。

**这与非对称签名有根本区别**（如 HTTPS 证书）。证书由 CA 的私钥签名，只有 CA 持有该私钥——因此有效的证书签名证明了 CA 签发了它。但 TLS 记录认证使用的是客户端和服务端都持有的对称密钥——因此有效的 MAC 不能证明是谁创建了它。

这就是为什么简单地将 TLS 记录转发给第三方不足以作为证据。需要在 TLS 会话期间进行某种形式的干预，以防止客户端单方面伪造数据。Half-MPC 协议通过分割 TLS 密钥来实现这一点——让任何一方都不能独自持有完整的密钥。

---

## 5. 背景知识：多方安全计算（MPC）

### 5.1 MPC 做了什么

多方安全计算允许两个或多个参与方在不向彼此泄露私有输入的情况下，联合计算一个函数。

数学表述：参与方 P₁ 和 P₂ 分别持有私有输入 x₁ 和 x₂。他们想要计算 f(x₁, x₂)，满足：
- 双方都得到输出 f(x₁, x₂)
- P₁ 不会了解到关于 x₂ 的任何信息（除了 f(x₁, x₂) 所揭示的）
- P₂ 不会了解到关于 x₁ 的任何信息（除了 f(x₁, x₂) 所揭示的）

对于 Half-MPC 协议，函数是 `AES(key, input)`，其中：
- Hub 持有 `key_H`（AES 密钥的一个 share）
- Provider 持有 `key_P`（AES 密钥的另一个 share）
- 完整密钥 `key = key_H ⊕ key_P`
- 任何一方都不应知道对方的 share 或完整密钥

### 5.2 混淆电路

混淆电路（Yao's protocol）是评估 AES 等布尔电路最实用的 2PC 技术。

**工作原理（简化版）：**

1. **电路表示**：将函数（如 AES）表示为布尔电路——一个由 AND 门和 XOR 门组成的网络。

2. **混淆**（由"混淆方"执行，如 Hub）：
   - 对电路中的每条线路生成两个随机**标签**：一个代表 0，一个代表 1
   - 对每个门，将输出标签在对应的输入标签下加密
   - 混淆后的门表允许持有正确输入标签的人解密出恰好一个输出标签——但不会泄露底层的比特值

3. **评估**（由"评估方"执行，如 Provider）：
   - 评估方收到混淆电路和对应其实际输入比特的标签
   - 评估方逐门处理：用两个输入标签解密门表中恰好一个条目，得到输出标签
   - 最终评估方拥有编码了计算结果的输出标签

4. **输出解码**：混淆方揭示哪些输出标签对应 0 和 1，允许评估方解码出结果

**AES-128 的布尔电路参数**：
- 输入：128 位密钥 + 128 位数据块 = 256 输入位
- 输出：128 位加密数据块
- 电路大小：约 **6,400 个 AND 门**和约 25,000 个 XOR 门
- XOR 门在 Free-XOR 优化下"免费"（零通信成本）
- 混淆门表总大小：约 6,400 × 16 字节 ≈ **每次 AES 评估约 100 KB**

### 5.3 不经意传输（OT）

评估方需要接收对应其实际输入比特的标签——但不能向混淆方泄露这些比特。这通过**不经意传输**实现：

- 混淆方持有评估方每条输入线路的两个标签：(label₀, label₁)
- 评估方持有选择位 b ∈ {0, 1}
- OT 完成后，评估方得到 label_b，混淆方完全不知道 b 的值

对于 AES 的 128 位私有输入，这需要 128 次 OT。通过 **OT Extension** 技术，大量 OT 的成本可以降低为少量基础 OT 加上廉价的对称密钥操作。

### 5.4 离线/在线分离

混淆电路协议天然分为两个阶段：

**离线阶段**（可以在实际输入已知之前完成）：
- 混淆方生成混淆电路和混淆表
- 建立 OT Extension 的基础 OT
- 这可以在空闲时间完成（如等待 LLM 响应时）

**在线阶段**（当需要实际计算时）：
- 通过 OT 传输输入标签（使用预建立的 OT Extension）
- 评估方处理混淆电路
- 解码输出

在线阶段极快——对于单次 AES 评估通常只需**微秒级别**——因为繁重的密码学工作已在离线阶段完成。

对于 Half-MPC 协议，这意味着：
- Hub 在空闲时间预生成未来 AES block 的混淆电路
- 当 Consumer 请求到达时，只需运行在线阶段（每请求约 0.5ms）

---

## 6. 协议设计

### 6.1 角色定义

| 角色 | 描述 |
|---|---|
| **Hub** | 中央调度服务器。接收 Consumer 请求，分配给 Provider，验证响应。由平台运营。 |
| **Provider** | 持有上游 API 密钥/令牌。使用自己的 IP 建立到上游 API 的 TCP 连接。参与 TLS 握手和请求加密的 MPC。 |
| **上游 API** | LLM API 服务器（如 `api.openai.com`）。不做任何修改；从 Provider 的 IP 看到一个标准的 TLS 连接。 |

### 6.2 Phase 0：MPC-TLS 握手（每条连接一次）

Hub 和 Provider 使用两方计算（2PC）联合执行 TLS 1.3 握手。TCP 连接从 Provider 的机器发起，因此上游 API 看到 Provider 的 IP。

```
Hub（验证方）            Provider（证明方）           api.openai.com
     |                        |                            |
     |                        |──TCP SYN──────────────────>|
     |                        |<─TCP SYN-ACK───────────────|
     |                        |──TCP ACK──────────────────>|
     |                        |                            |
     |<=== MPC 通道 =========>|                            |
     |                        |                            |
     |  联合 ECDH：            |                            |
     |  Hub 输入：a_H          |                            |
     |  Provider 输入：a_P     |                            |
     |  2PC 计算：             |                            |
     |    a = a_H + a_P (mod n)                            |
     |    g^a = 客户端 ECDH 公钥                             |
     |    shared_secret = (g^b)^a                          |
     |                        |                            |
     |                        |──ClientHello(g^a)────────> |
     |                        |<─ServerHello(g^b)────────── |
     |                        |<─{Certificate}───────────── |
     |                        |<─{CertificateVerify}─────── |
     |                        |<─{Finished}──────────────── |
     |                        |                            |
     |  联合 HKDF：            |                            |
     |  2PC 将 traffic secrets |                            |
     |  派生为 XOR shares      |                            |
     |                        |                            |
     |  Hub 得到：             |  Provider 得到：            |
     |    cts_H (client share) |    cts_P (client share)    |
     |    sts_H (server share) |    sts_P (server share)    |
     |                        |                            |
     |  Hub 验证服务端证书链    |                            |
     |  （确认连接目标是        |                            |
     |   api.openai.com）      |                            |
     |                        |                            |
     |                        |──{Finished}──────────────> |
     |                        |                            |
```

**握手期间的 MPC 操作：**

1. **ECDH 密钥交换**：Hub 持有私钥份额 `a_H`，Provider 持有 `a_P`。通过 2PC，双方联合计算 ECDH 共享密钥，任何一方都不会知道对方的份额或完整的共享密钥。

2. **HKDF 密钥派生**：共享密钥被输入 HKDF（基于 HMAC）。通过对 HMAC 电路的 2PC，双方获得 traffic secrets 的 XOR 份额：

```
client_application_traffic_secret:
  Hub 持有：    cts_H     （随机 256 位份额）
  Provider 持有：cts_P     （随机 256 位份额）
  实际密钥：    cts = cts_H ⊕ cts_P

server_application_traffic_secret:
  Hub 持有：    sts_H     （随机 256 位份额）
  Provider 持有：sts_P     （随机 256 位份额）
  实际密钥：    sts = sts_H ⊕ sts_P
```

3. **服务端证书验证**：Hub 验证服务端的证书链（确保 TLS 连接的目标是 `api.openai.com` 而非冒充者）。证书是握手记录的一部分，Hub 通过 MPC 协议可以看到。

**开销**：约 2-5 秒（主要是 ECDH 标量乘法的混淆电路评估）。**每条 TLS 连接只做一次**，摊薄到所有后续 HTTP 请求。

### 6.3 Phase 1：非对称密钥分配

这是 Half-MPC 设计的核心洞察。MPC 握手完成后，**server traffic secret** 被完整交给 Hub：

```
Provider ──sts_P──> Hub       （Provider 发送其 server secret 份额）

Hub 计算：
  server_traffic_secret = sts_H ⊕ sts_P         （Hub 现在知道完整密钥）
  server_write_key = HKDF-Expand-Label(sts, "key", "", 16)
  server_write_iv  = HKDF-Expand-Label(sts, "iv", "", 12)
```

**client traffic secret 保持秘密共享**：

```
client_application_traffic_secret:
  Hub 持有：    cts_H     （不变，随机份额）
  Provider 持有：cts_P     （不变，随机份额）
  任何一方都无法重建：cts = cts_H ⊕ cts_P
```

**结果的密钥分配：**

| 密钥材料 | Hub 知道？ | Provider 知道？ | 用途 |
|---|---|---|---|
| `client_traffic_secret` | 仅知道份额 `cts_H` | 仅知道份额 `cts_P` | 加密请求（client→server） |
| `server_traffic_secret` | ✅ 完整 | ❌ 已丢弃份额 | 解密响应（server→client） |

**为什么这是安全的**：如 §4.5 所述，client 和 server 的 traffic secrets 是通过独立的 HKDF-Expand-Label 调用从 Master Secret 派生的。知道 server traffic secret 不会泄露 client traffic secret。Provider 的 API 密钥受 client traffic secret 保护，而它仍然是分割的。

### 6.4 Phase 2：请求加密（每次请求）

当 Consumer 请求到达时，Hub 必须构造 HTTP 请求并将其加密为 TLS 记录。HTTP 请求包含**公开字段**（Hub 知道的）和一个**秘密字段**（仅 Provider 知道的 API 密钥）。

#### HTTP 请求结构

```http
POST /v1/chat/completions HTTP/1.1\r\n       ← Hub 知道
Host: api.openai.com\r\n                      ← Hub 知道
Authorization: Bearer sk-proj-xxxx...\r\n     ← 仅 Provider 知道
Content-Type: application/json\r\n            ← Hub 知道
Content-Length: 142\r\n                        ← Hub 知道
\r\n
{"model":"gpt-4o","messages":[...]}           ← Hub 知道（Consumer 的 prompt）
```

#### AES Block 布局

序列化并拆分为 16 字节的 AES-CTR blocks：

```
Block  0: "POST /v1/chat/c"       ← 公开（Hub 知道明文）
Block  1: "ompletions HTTP"       ← 公开
Block  2: "/1.1\r\nHost: ap"      ← 公开
Block  3: "i.openai.com\r\n"      ← 公开
Block  4: "Authorization: "       ← 公开（header 名称）
Block  5: "Bearer sk-proj-"       ← 秘密（API 密钥开始）
Block  6: "xxxxxxxxxxxxxxxx"      ← 秘密（API 密钥主体）
Block  7: "xxxx\r\nContent-"      ← 秘密（API 密钥结束）
Block  8: "Type: applicatio"      ← 公开
Block  9: "n/json\r\nConten"      ← 公开
...
Block  N: "...prompt..}}\x17"     ← 公开（+ TLS content type 字节 0x17）
```

只有 **3-4 个 blocks**（48-64 字节）包含 API 密钥。典型请求总共有 30-50+ 个 blocks。

#### 加密协议

**步骤 1：公开 blocks 的密钥流生成**

对于 Hub 知道全部明文的 blocks（大多数 blocks）：

```
2PC 混淆电路：
  Hub 输入：     cts_H, nonce, counter_i
  Provider 输入：cts_P

  电路内部计算：
    client_key = cts_H ⊕ cts_P           // 在电路内部重建密钥
    keystream[i] = AES(client_key, nonce ∥ counter_i)

  输出 → 双方都收到 keystream[i]
  （这是安全的：Hub 知道这些 blocks 的明文，所以密钥流
   结合 Hub 已知的明文不会向 Hub 泄露新信息。
   Provider 已经知道自己的密钥份额。）

Hub 本地计算：
  ciphertext[i] = known_plaintext[i] ⊕ keystream[i]
```

**步骤 2：秘密 blocks 的加密（包含 API 密钥）**

对于 blocks 5-7（包含 API 密钥）：

```
2PC 混淆电路：
  Hub 输入：     cts_H, nonce, counter_i, header_template[i]
                 （如 "Bearer " 填充或 "\r\nContent-" 后缀）
  Provider 输入：cts_P, api_key_bytes[i]
                 （该 block 位置的 API 密钥字节）

  电路内部计算：
    client_key = cts_H ⊕ cts_P
    plaintext[i] = merge(header_template[i], api_key_bytes[i])
    keystream[i] = AES(client_key, nonce ∥ counter_i)
    ciphertext[i] = plaintext[i] ⊕ keystream[i]

  输出 → ciphertext[i] 仅给 Hub
```

**为什么 Hub 无法恢复 API 密钥**：
- Hub 收到 `ciphertext[i]` 但**不**收到秘密 blocks 的 `keystream[i]`
- Hub 不知道 `cts_P`，因此无法本地计算 `client_key` 或 `keystream[i]`
- 没有 `keystream[i]`，Hub 就无法反转 `ciphertext[i] ⊕ keystream[i]` 来获得 `plaintext[i]`
- 因此，`plaintext[i]` 中的 API 密钥字节对 Hub 保持隐藏

**步骤 3：GCM 认证标签**

```
2PC 混淆电路：
  Hub 输入：     cts_H, nonce
  Provider 输入：cts_P

  电路计算：
    client_key = cts_H ⊕ cts_P
    H = AES(client_key, 0^128)             // GHASH 的哈希子密钥
    J0 = AES(client_key, nonce ∥ 0^32)     // 最终 tag 异或的掩码

  输出 → H 和 J0 仅给 Hub

Hub 本地计算 GHASH（这是对密文的公开多项式求值）：
  tag = GHASH(H, AAD, all_ciphertext_blocks) ⊕ J0
```

GHASH 可以本地计算，因为它操作的是密文（Hub 此时已拥有所有 blocks 的密文）和 H/J0（电路输出给 Hub 的）。不需要任何私有输入。

**步骤 4：组装并转发**

```
Hub 组装完整 TLS 记录：
  record = TLS_header(5 字节) ∥ 所有密文 blocks ∥ tag(16 字节)

Hub ──记录字节──> Provider ──TCP socket.write()──> api.openai.com
```

Provider 只是将原始字节写入其 TCP 连接。它不解析、不解密、不检查 TLS 记录。上游 API 从 Provider 的 IP 地址收到一条完全有效的 TLS 记录。

### 6.5 Phase 3：响应解密（每次请求）

上游 API 用 **server write key** 加密其响应，并通过 Provider 的 TCP 连接发回：

```
api.openai.com ──加密的 TLS records──> Provider ──TCP 转发──> Hub
```

Provider 不做任何处理，直接转发原始密文字节给 Hub。

**Hub 本地解密——不涉及 MPC：**

```
对收到的每条 TLS 记录：

  1. 解析记录头（5 字节）获取有效载荷长度
  2. 将有效载荷分为密文和 tag（最后 16 字节）
  3. 构造 nonce：
       nonce = server_write_iv ⊕ sequence_number
  4. 验证并解密：
       plaintext = AES-GCM-Decrypt(server_write_key, nonce, AAD, ciphertext, tag)

  如果 tag 验证失败：
    → 记录被篡改（Provider 在传输中修改了密文）
    → 拒绝该响应并标记 Provider

  如果 tag 验证通过：
    → 明文保证是 api.openai.com 发送的原始内容
    → 任何修改都不可能通过 tag 验证
    → 提取 HTTP 响应数据（包括 SSE 流式块）
```

**这就是 "Half-MPC" 的含义**：响应解密**零 MPC 开销**。Hub 持有完整的 server traffic key 并独立解密。由于 LLM 响应通常比请求大得多（数百到数千个 token，跨越多条 TLS 记录），从响应路径中消除 MPC 去除了绝大部分计算开销。

对于 **SSE 流式传输**（Server-Sent Events，LLM 流式响应的标准格式）：
- 每个 SSE 块可能跨越一条或多条 TLS 记录
- Hub 在收到每条 TLS 记录时即时解密，无缓冲延迟
- 解密后的块实时转发给 Consumer
- 延迟与直接连接完全相同（此路径零 MPC 开销）

### 6.6 Phase 4：验证与结算

每个请求-响应周期完成后，Hub 拥有：

1. Consumer 的原始 prompt（Hub 构造了请求）
2. 来自上游 API 的**已验证、已解密**的响应（用 server key 解密；tag 验证证明真实性）
3. TLS 连接指向 `api.openai.com` 的证明（Phase 0 中的 MPC 握手期间验证了服务端证书）
4. 响应元数据，包括上游 API 返回的 `x-request-id`、`openai-processing-ms` 和 `usage` 字段

Hub 可以：
- **转发**已验证的响应给 Consumer
- **计量** token 用量（从响应的 `usage` 字段获取 input_tokens、output_tokens）
- **计费** Consumer 并相应地向 Provider 支付
- **记录**验证结果用于审计和争议解决

---

## 7. 为什么叫 "Half-MPC"

该协议选择性地仅将 MPC 应用于数据流的一个方向：

```
                    需要 MPC？       原因
                    ─────────       ────
请求方向
(client → server):  ✅ 是           Client key 是秘密共享的；
                                     API 密钥是 Provider 的私有输入。
                                     MPC 确保任何一方都无法
                                     单方面构造请求。

响应方向
(server → client):  ❌ 否           Server key 完整由 Hub 持有。
                                     Hub 独立解密和验证响应。
                                     Provider 只转发密文。
```

这种非对称性之所以可能，是因为 TLS 1.3 为每个方向派生**独立的密钥**（§4.5）。向 Hub 揭示 server→client 密钥不会危及 client→server 密钥。

**这种非对称性的安全影响：**

| 能力 | Hub | Provider |
|---|---|---|
| 解密服务端响应 | ✅（拥有 server key） | ❌（没有密钥） |
| 伪造 server 方向的 TLS 记录 | ✅ 理论上可以 | ❌ |
| 构造 client 方向的 TLS 记录 | ❌（只有 client key 的份额） | ❌（只有 client key 的份额） |
| 获知 API 密钥 | ❌（被 client 方向的 MPC 保护） | ✅（是他们自己的密钥） |
| 验证响应真实性 | ✅（用 server key 检查 GCM tag） | ❌（没有密钥用于验证） |

Hub 伪造 server 方向记录的能力在实践中不是问题：Provider 从不检查或验证 server 方向的记录（它只转发原始字节），而且 Hub 没有动机向自己的 Consumer 伪造响应。

---

## 8. 安全性分析

### 8.1 Provider 攻击

| 攻击 | 是否防御？ | 防御机制 |
|---|---|---|
| 替换更便宜的模型 | ✅ | Hub 解密已验证的响应并检查模型字段、响应时序和内容特征 |
| 修改 Consumer 的 prompt | ✅ | Hub 构造请求明文（API 密钥除外）；任何修改都会在上游服务器处破坏 GCM tag |
| 篡改上游响应 | ✅ | Hub 使用 server key 验证 GCM 认证标签；传输中的任何比特翻转都会被检测 |
| 不调用 API 直接伪造响应 | ✅ | Provider 没有 server key；无法创建带有效 GCM tag 的记录 |
| 重定向到其他 API 服务器 | ✅ | MPC 握手期间验证了服务端证书；Hub 确认服务器身份是 `api.openai.com` |
| 重放之前的响应 | ✅ | TLS 序列号单调递增；重放的记录 nonce 错误，tag 验证失败 |

### 8.2 Hub 攻击

| 攻击 | 是否防御？ | 防御机制 |
|---|---|---|
| 获知 Provider 的 API 密钥 | ✅ | Client key 是秘密共享的；API 密钥 blocks 在 2PC 电路内加密；Hub 收到密文但不收到密钥流 |
| 独立使用 Provider 的 API 密钥 | ✅ | Hub 没有 Provider 的密钥份额，无法构造有效的 client 方向 TLS 记录 |
| 向 Consumer 伪造响应 | ❌（Hub 被信任） | Hub 理论上可以构造假的 server 记录（拥有密钥），但这会损害其平台声誉 |
| 窃听 Consumer 的 prompt | ⚠️ 固有的 | Hub 构造 HTTP 请求体——它必然看到 prompt。Prompt 隐私需要额外措施（如 Hub 侧 TEE） |

### 8.3 外部攻击

| 攻击 | 是否防御？ | 防御机制 |
|---|---|---|
| 网络窃听 | ✅ | Provider↔API 路径上的标准 TLS 加密；Hub↔Provider MPC 通道使用独立加密 |
| 中间人攻击 | ✅ | 握手期间的服务端证书验证（Hub 验证证书链） |
| 重放攻击 | ✅ | TLS 序列号；每条记录使用新的 nonce |

---

## 9. 性能分析

### 9.1 MPC 操作开销

AES-128 实现为布尔电路需要约 **6,400 个 AND 门**（XOR 门在 Free-XOR 优化下免费）。

| 操作 | AES 求值次数 | AND 门数 | 预估耗时 |
|---|---|---|---|
| **Phase 0**：ECDH + HKDF（每连接一次） | N/A | ~500,000 | 2-5 秒 |
| **Phase 2**：公开 block 密钥流（每 block） | 1 | 6,400 | ~0.05ms |
| **Phase 2**：秘密 block 加密（每 block） | 1 | 6,400 | ~0.05ms |
| **Phase 2**：GCM H 和 J0 派生（每条记录） | 2 | 12,800 | ~0.1ms |
| **Phase 3**：响应解密（每条记录） | 0（本地 AES） | 0 | 0ms MPC 开销 |

### 9.2 每请求开销分解

对于典型的 LLM API 请求（30 个公开 blocks + 4 个秘密 blocks + GCM tag 计算）：

```
请求加密 MPC：(30 + 4) × 0.05ms + 0.1ms ≈ 1.8ms
响应解密：    0ms（Hub 本地解密）
──────────────────────────────────────────────────
总 MPC 开销：~2ms/请求
```

使用离线预计算（空闲时间生成混淆电路）：

```
仅在线开销：~0.5ms/请求
```

### 9.3 端到端延迟影响

| 组件 | 延迟 | 在关键路径上？ |
|---|---|---|
| MPC-TLS 握手（Phase 0） | 2-5 秒 | 否（在连接池中预热） |
| 请求加密 MPC（Phase 2） | ~2ms（预计算后约 0.5ms） | 是 |
| 响应解密（Phase 3） | ~0ms 额外开销 | 否（Hub 本地解密，和普通 TLS 一样快） |
| 上游 API 的 LLM 推理 | 500ms – 30s | 是（基线，不可避免） |
| **实际开销** | **~2ms** | **相对于 LLM 推理时间可忽略** |

### 9.4 带宽开销

| 通道 | 额外带宽 |
|---|---|
| Hub ↔ Provider（MPC） | 每次握手约 200KB；每次请求约 50KB（混淆电路）。预计算后：每次请求在线约 5KB。 |
| Provider ↔ 上游 API | 零（标准 TLS；Provider 只是转发字节） |
| Hub → Consumer | 零（标准 HTTP 响应转发） |

---

## 10. 连接池与生命周期管理

### 10.1 预热

为了将握手延迟从请求路径中隐藏，Hub 维护一个预建立的 MPC-TLS 连接池：

```
Hub 启动 / 后台循环：
  对每个已注册的 Provider：
    1. 建立 2 个 MPC-TLS 连接（后台，不阻塞请求）
    2. 预生成约 100 个 AES block 评估的混淆电路

当 Consumer 请求到达：
    1. 从目标 Provider 的池中取一个空闲的预热连接
    2. 使用预生成的混淆电路进行请求加密（仅在线阶段）
    3. 处理请求
    4. 将连接归还池
    5. 后台：补充未来请求的混淆电路存量

如果没有预热连接可用：
    建立新的 MPC-TLS 连接（此首次请求有 2-5 秒延迟）
```

### 10.2 连接生命周期

```
          MPC 握手（2-5s，一次性）
                     │
                     ▼
┌──── 活跃的 TLS 连接（可复用） ────┐
│                                   │
│  请求 1 → MPC 加密 → 转发        │
│  响应 1 ← Hub 解密 ← 转发        │
│                                   │
│  请求 2 → MPC 加密 → 转发        │
│  响应 2 ← Hub 解密 ← 转发        │
│                                   │
│  ...                              │
│                                   │
│  维护策略：                        │
│  • 空闲超时：60s（不用则关闭）     │
│  • 密钥更新：每 100 请求或 5 分钟  │
│  • 最大生存时间：30 分钟           │
│  • 错误恢复：关闭 + 重新建立      │
│                                   │
└───────────────────────────────────┘
                     │
                     ▼
             连接关闭
        （后台预热新连接）
```

### 10.3 密钥更新处理

当触发 TLS Key Update 时（由服务端触发或 Hub 主动触发）：

**Client traffic secret 更新**（秘密共享的）：

```
Hub 和 Provider 运行轻量级 2PC-HMAC：

  2PC 输入：
    Hub：    当前的 cts_H
    Provider：当前的 cts_P

  2PC 计算：
    current_cts = cts_H ⊕ cts_P
    new_cts = HKDF-Expand-Label(current_cts, "traffic upd", "", 32)
    new_cts_H = random()
    new_cts_P = new_cts ⊕ new_cts_H

  输出：
    Hub 得到：    new_cts_H
    Provider 得到：new_cts_P

开销：~1ms（一个 HMAC 电路，比 AES 小得多）
```

**Server traffic secret 更新**（Hub 持有完整密钥）：

```
Hub 本地计算：
  new_sts = HKDF-Expand-Label(current_sts, "traffic upd", "", 32)
  new_server_write_key = HKDF-Expand-Label(new_sts, "key", "", 16)
  new_server_write_iv  = HKDF-Expand-Label(new_sts, "iv", "", 12)

开销：~0ms（本地 HMAC，无 MPC）
```

---

## 11. 与替代方案的对比

| 维度 | 自签名收据 | TEE 证明 | 完整 MPC-TLS | 代理模式 | **Half-MPC（本方案）** |
|---|---|---|---|---|---|
| **证明响应来源** | ❌ 自证 | ✅ 硬件 | ✅ 密码学 | ✅ ZK 证明 | ✅ 密码学 |
| **特殊硬件** | 无 | Intel TDX + NVIDIA CC | 无 | 无 | **无** |
| **API 密钥隐私** | N/A | ✅ 在飞地中 | ✅ 共享 | ⚠️ 取决于模式 | **✅ 秘密共享** |
| **上游看到的 IP** | Provider | Provider | Provider | Hub ❌ | **Provider ✅** |
| **每请求开销** | ~0ms | ~0ms | ~数秒 | ~0ms 在线 | **~2ms** |
| **响应解密** | ~0ms | ~0ms | ~数秒 ❌ | ~0ms | **~0ms（本地）** |
| **握手开销** | 无 | ~30s 证明 | 每请求 ❌ | 每连接 | **每连接（可摊薄）** |
| **信任假设** | 信任 Provider | 信任硬件厂商 | 最小 | 信任代理 + ZK | **信任 Hub 进行响应转发** |
| **工程复杂度** | 低 | 高（硬件 + 运维） | 极高 | 高（ZK 电路） | **中等** |

### 相对于完整 MPC-TLS 的优势

1. **响应解密免费**：server→client 方向零 MPC。LLM 响应（数据量的主体）无 MPC 开销。
2. **更简单的电路**：只需要 AES 加密电路，不需要完整的 TLS 记录处理状态机。
3. **更好的流式支持**：Hub 在收到 SSE 块时本地即时解密——每个块不需要 MPC 往返。

### 相对于 TEE 的优势

1. **无硬件要求**：任何通用服务器或云实例都可以。
2. **无厂商信任**：不需要信任 Intel/AMD 的 TEE 实现或固件更新流程。
3. **密码学保证**：安全性基于数学困难性假设（ECDH、AES），而非硬件正确性。

### 相对于代理模式的优势

1. **Provider IP 保留**：上游 API 看到 Provider 的 IP，不是 Hub 的。无封号风险。
2. **API 密钥隐私**：Hub 无法获知 Provider 的 API 密钥。

---

## 12. 实现建议

### 12.1 推荐技术栈

| 组件 | 技术 | 理由 |
|---|---|---|
| Hub 服务器 | Go | 现有代码库；高性能网络 |
| Provider App | Go | 现有代码库；Go 中 TCP 转发很简单 |
| MPC 库 | Rust（`mpz` / `tlsn` crate） | TLSNotary 的成熟 2PC 原语，专为 TLS 优化 |
| Go ↔ Rust 桥接 | 子进程或 FFI（cgo） | MPC 模块作为 Rust sidecar 进程运行 |
| MPC 传输 | WebSocket（现有的 Hub↔Provider 通道） | 复用现有基础设施 |

### 12.2 与 TLSNotary 的集成

`tlsn` crate（TLSNotary 的 Rust 实现）已经提供：

- 2PC-AES 混淆电路实现（用 Free-XOR 和 half-gates 优化）
- 不经意传输扩展（IKNP 协议）
- TLS 1.3 MPC 握手协议
- HKDF 和 HMAC MPC 电路

Half-MPC 协议可以通过以下方式构建：

1. **复用** `tlsn` 的 MPC-TLS 握手模块（Phase 0）
2. **修改**握手后阶段，将 `server_traffic_secret` 揭示给 Hub（Phase 1——小的协议变更）
3. **使用** `tlsn` 的 2PC-AES 原语进行逐 block 的请求加密（Phase 2）
4. **实现**标准 AES-GCM 解密（Go 或 Rust）（Phase 3——不需要 MPC 库）

### 12.3 Provider App 变更

Provider App 的角色显著简化：

**新职责：**
1. TCP 连接管理：建立和维护到上游 API 的 TCP 连接
2. MPC 参与：运行 Rust MPC sidecar 进行握手和请求加密
3. 字节转发：在 Hub 和上游 API 之间中继 TLS 记录字节（Go 中的 `io.Copy`）

**不再需要的：**
- HTTP 请求/响应解析（Hub 处理）
- 直接使用 TLS 库（Hub 通过 MPC 驱动 TLS；Provider 只转发字节）
- 在 HTTP headers 中直接使用 API 密钥（密钥通过 MPC 电路注入）

### 12.4 分阶段部署

该协议可以渐进式部署：

**阶段 1 — 基线（首先部署）：**
使用更简单的 "Wokey" 模型，Hub 持有完整 TLS 密钥和 Provider 的 API 密钥。验证 TCP 隧道架构和商业模式，零 MPC 复杂度。

**阶段 2 — Half-MPC（当 API 密钥隐私重要时部署）：**
升级到完整的 Half-MPC 协议。阶段 1 的 TCP 隧道架构保持不变。唯一的添加是 Hub 和 Provider 上的 MPC sidecar，处理密钥共享和请求加密。Provider App 变更最小（添加 sidecar 进程管理）。

**阶段 3 — 概率抽样（可选优化）：**
对随机样本（如 5%）的请求使用 Half-MPC 验证。未抽样的请求使用更简单的 Wokey 模型。结合质押/惩罚机制，在将稳态 MPC 开销降到近零的同时保持对作弊的经济威慑。

---

## 13. 局限性与未来工作

### 13.1 当前局限性

1. **Prompt 隐私**：Hub 看到 Consumer 的 prompt（它构造 HTTP 请求）。完全的 prompt 隐私需要完整 MPC-TLS（两个方向）或 Hub 侧的 TEE（如 AWS Nitro Enclave）。

2. **Hub 的响应递送信任**：虽然 Hub 密码学验证了响应，Consumer 必须信任 Hub 如实地转发响应。恶意 Hub 理论上可以抑制或替换响应（使用其持有的 server key）。缓解措施：使验证承诺可独立审计。

3. **连接开销**：每个 Provider 需要预建立的 MPC-TLS 连接。当 Provider 数量众多时，连接池管理变得复杂。连接预热失败需要优雅处理。

4. **上游 API 兼容性**：协议假设 TLS 1.3 配合 AES-GCM。如果上游 API 协商不同的密码套件（如 ChaCha20-Poly1305），MPC 电路需要支持该密码。TLS 1.2 需要不同的处理（独立的 MAC 密钥 vs AEAD）。

### 13.2 未来增强

1. **链上争议解决**：在链上发布验证承诺（已验证响应 + 元数据的哈希）。争议时，MPC 记录可作为密码学证据。

2. **ZK 验证证明**：Hub 验证响应后，生成一个简洁的 ZK 证明，证明验证是正确执行的。这消除了 Consumer 对 Hub 的信任依赖。

3. **模型指纹集成**：结合 TLS 绑定（证明字节来自上游 API）和黑盒模型指纹（证明上游 API 提供的是声称的模型，而非更便宜的替代品）。TLS 绑定处理传输层归属；指纹处理应用层模型身份。

4. **LLM 定价预言机**：将上游 API 定价数据聚合到链上。Provider 的定价可以对照预言机参考价格验证，增加经济公平层。

---

*文档版本：2.0*
*最后更新：2026 年 8 月*
