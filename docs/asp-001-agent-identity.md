# ASP-001 Agent Identity

状态：Draft 0  
范围：定义 Agent Space MVP 的 Agent ID 计算方式、别名规则和独立性保证。

## 1. 目标

Agent ID 必须满足：

- 不依赖 IP。
- 不依赖 DNS。
- 不依赖 HTTP URL。
- 不依赖中心注册服务器。
- 可以被任意接收方本地验证。
- Agent 迁移 Zone 或 transport 后，身份不变。

最小可行方案：用公钥自证明身份。

## 2. 两层身份

Agent Space MVP 使用三种标识：

```text
aid:       canonical identity，自证明身份
zid:       Zone identity，自证明治理域身份
agent://   routable alias，人类可读和 Zone 可路由别名
```

示例：

```text
aid:ed25519:W6hJz3c9bQ0RZK2Vj1v2m1jNn9CzYxR0a9f8h2LqT7k
agent://acme/security.audit.v1
```

`aid:` 是身份。  
`zid:` 是 Zone 身份。  
`agent://` 是路由名，由 Zone 签名绑定到 `aid:`。

不要把三者混成一个东西。

## 3. aid 计算

MVP 只支持 Ed25519。

输入：

```text
public_key = DER-encoded SubjectPublicKeyInfo for an Ed25519 public key
```

计算：

```text
digest = SHA-256("asp-agent-id-v1\0" || public_key)
key_id = base64url_no_padding(digest)
aid = "aid:ed25519:" || key_id
```

说明：

- SHA-256 用标准库即可。
- SubjectPublicKeyInfo 是标准公钥编码，避免手写 Ed25519 raw key 解析。
- base64url 不带 `=` padding，方便放进 URI 和 JSON。
- `"asp-agent-id-v1\0"` 是 domain separator，避免同一公钥哈希在别的协议里被误用。
- 不截断 digest。43 个 base64url 字符不值得省，碰撞风险更低。

伪代码：

```python
digest = sha256(b"asp-agent-id-v1\0" + public_key_spki_der).digest()
key_id = base64url(digest).rstrip("=")
aid = "aid:ed25519:" + key_id
```

## 4. 独立性保证

`aid:` 的独立性来自私钥控制权。

任何节点拿到：

```text
aid
public_key
signature
message
```

都可以本地验证：

1. `public_key` 是否能重新计算出 `aid`。
2. `signature` 是否由该 `public_key` 签出。

因此身份不依赖：

- 当前 IP
- 当前域名
- 当前 Zone
- 当前 registry
- 当前 transport
- 当前平台账号

Zone 可以拒绝某个 Agent 进入本 Zone，但不能伪造或“拥有”这个 Agent 的 `aid:`。

## 5. agent:// 别名

`agent://` 是 Zone 内或联邦网络中的可路由别名。

格式：

```text
agent://<zone>/<name>
```

示例：

```text
agent://personal.xxyu/codex.builder
agent://acme/security.audit.v1
```

解析结果必须返回 Agent Descriptor，其中包含 canonical `aid:`。

```json
{
  "alias": "agent://acme/security.audit.v1",
  "aid": "aid:ed25519:W6hJz3c9bQ0RZK2Vj1v2m1jNn9CzYxR0a9f8h2LqT7k",
  "public_key": "ed25519:...",
  "transports": ["asp+ws://127.0.0.1:8787"],
  "signature": "..."
}
```

MVP 中，alias 由本地 Zone Registry 管理，并由 Zone key 签名绑定到 Agent `aid:`。

## 5.1 zid 计算

Zone ID 也使用 Ed25519 公钥自证明，但使用不同 domain separator：

```text
digest = SHA-256("asp-zone-id-v1\0" || zone_public_key_spki_der)
zid = "zid:ed25519:" || base64url_no_padding(digest)
```

Agent 身份和 Zone 身份使用不同前缀与 domain separator，避免跨类型混用。

## 6. Descriptor 签名

Agent Descriptor 必须由 Agent 私钥签名。

如果 alias 属于某个 Zone，还可以由 Zone 私钥附加签名。

```text
agent_signature = Agent 对 descriptor 内容签名
zone_signature  = Zone 对 alias -> aid 绑定签名
```

MVP 要求 `descriptor_signature`。签名内容是 descriptor 去掉 `descriptor_signature` 字段后的 canonical JSON。

Zone 签名延后到联邦阶段。

## 7. Agent Principal 与 Instance

一个长期 Agent 身份可能有多个运行实例。

因此拆成：

```text
Agent Principal ID = 长期身份 aid
Agent Instance ID  = 某次运行实例 iid
```

MVP 可以先不实现 `iid`。

但概念上要保留：如果同一个 Agent 在三台机器上运行，它们共享同一个 principal，但每个 runtime instance 应该有不同 `iid`。

延后原因：MVP 先证明身份和任务闭环，多实例调度暂时不需要。

## 8. 密钥轮换

MVP 可以不做自动轮换，但规范要留接口。

轮换需要双签：

```text
old_key signs new_aid
new_key signs old_aid
```

Descriptor 中保留：

```json
{
  "previous_aid": "aid:ed25519:...",
  "rotated_at": "2026-07-02T00:00:00Z"
}
```

没有旧私钥时不能无缝继承身份，只能创建新 Agent。

这是故意的：身份独立性来自私钥，丢了私钥就丢了身份控制权。

## 9. 克隆问题

如果两个进程持有同一个私钥，它们在协议上就是同一个 Agent。

MVP 不解决私钥被复制后的物理区分问题。

后续用 `iid`、硬件证明、Zone attestation 或运行时证书区分实例。

## 10. 为什么不用 DNS 或 DID 作为 MVP 核心

DNS 可以作为 bootstrap，但不能作为 Agent 身份。

DID 可以后续兼容，但 MVP 不需要完整 DID method、DID document 和 resolver 生态。

最小方案是：

```text
公钥 -> aid
签名 -> 验证控制权
registry -> alias 和 transport
```

这已经足够证明 Agent ID 独立于 Internet 寻址体系。

## 11. MVP 验证用例

测试必须证明：

1. 同一个 public key 总是计算出同一个 `aid:`。
2. 任意修改 public key 都会得到不同 `aid:`。
3. Agent 使用私钥签名任务后，接收方能用 descriptor 里的 public key 验证。
4. 修改 task 内容会导致签名验证失败。
5. `agent://` alias 换 transport 后，`aid:` 不变。

这五条够了。
