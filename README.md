# Zero Trust Gateway（本地版，Java / Spring Boot）

为现有 Web 应用提供一套**纯本地、可离线运行**的零信任请求校验能力：
多来源凭证统一鉴权、按调用主体限流配额、请求防重放/防篡改。
所有状态与密钥都在本地配置和内存中完成，**不依赖任何外部服务或真实凭证**。

受保护资源为演示端点 `POST /api/echo`（原样回显请求体）。

---

## 1. 凭证兼容范围

凭证在 `src/main/resources/application.properties` 的 `ztg.credentials[*]` 中登记，
应用启动时一次性加载到内存凭证库。每份凭证包含：

| 字段 | 含义 |
| --- | --- |
| `key-id` | 凭证标识，对应请求头 `X-ZT-Key-Id` |
| `secret` | 共享密钥（仅本地演示值，非真实凭证） |
| `type` | 凭证类型/版本：`V1_HMAC_SHA1` 或 `V2_HMAC_SHA256` |
| `principal` | 归一化后的**统一调用主体** |
| `expires-at` | 失效时间（UTC） |

预置凭证：

| keyId | 类型 | 归一主体 | 说明 |
| --- | --- | --- | --- |
| `demo-key-v1` | V1 / HMAC-SHA1 | `svc-demo` | 兼容旧版本调用方 |
| `demo-key-v2` | V2 / HMAC-SHA256 | `svc-demo` | 当前推荐版本，与 v1 归一到同一主体 |
| `partner-key-v2` | V2 / HMAC-SHA256 | `svc-partner` | 另一来源，限流配额独立 |
| `expired-key-v1` | V1 / HMAC-SHA1 | `svc-expired` | 已过期，用于验证 `CREDENTIAL_EXPIRED` |

**不同类型/版本的凭证走完全相同的判定流程**，唯一差异是签名算法：

* `V1_HMAC_SHA1` → `HmacSHA1`（兼容）
* `V2_HMAC_SHA256` → `HmacSHA256`（推荐）
* 请求体摘要统一为 `SHA-256`
* 十六进制输出，签名比较使用常量时间比较（`MessageDigest.isEqual`）

### 请求头

| 头 | 说明 |
| --- | --- |
| `X-ZT-Key-Id` | 凭证标识 |
| `X-ZT-Principal` | 调用方自述主体（可选；提供时必须与凭证归一主体一致） |
| `X-ZT-Timestamp` | Unix 秒 |
| `X-ZT-Nonce` | 请求唯一标识 |
| `X-ZT-Sequence` | 同一主体内严格单调递增的序号 |
| `X-ZT-Body-Sha256` | 请求体 SHA-256 十六进制（防篡改） |
| `X-ZT-Signature` | 对规范串计算的 HMAC 十六进制 |

### 规范串（字段间 `\n` 分隔）

```
method
path
timestamp
nonce
sequence
bodySha256
```

---

## 2. 鉴权与限流规则

判定顺序固定，**每个失败点对应唯一拒绝码**，结论可解释且同一输入稳定可复现：

| # | 判定点 | 拒绝原因（`reason`） | HTTP |
| --- | --- | --- | --- |
| 1 | 缺少 `X-ZT-Key-Id` | `MISSING_CREDENTIAL` | 401 |
| 2 | 时间戳/序号/nonce/摘要/签名头缺失或非数字 | `MALFORMED_REQUEST` | 401 |
| 3 | keyId 未在本地登记 | `UNKNOWN_KEY_ID` | 401 |
| 4 | 凭证已过 `expires-at` | `CREDENTIAL_EXPIRED` | 401 |
| 5 | 自述主体 ≠ 凭证归一主体（越权） | `PRINCIPAL_MISMATCH` | 401 |
| 6 | 请求体实际摘要 ≠ `X-ZT-Body-Sha256`（篡改） | `BODY_TAMPERED` | 401 |
| 7 | HMAC 签名不符（含用错密钥/版本） | `SIGNATURE_MISMATCH` | 401 |
| 8 | `|now - timestamp|` 超过窗口（默认 30s） | `STALE_TIMESTAMP` | 409 |
| 9 | 主体配额用尽（固定窗口） | `RATE_LIMITED` | 429 |
| 10 | nonce 在 TTL 内重复（并发也只放过一次） | `NONCE_REPLAY` | 409 |
| 11 | 序号未严格递增（回退/相等） | `SEQUENCE_ROLLBACK` | 409 |

三类问题状态码彼此分离：**鉴权 401 / 重放冲突 409 / 限流 429**，
响应体统一为 JSON：`{"allowed":false,"reason":"...","detail":"...","keyId":"...","principal":"..."}`。

### 限流（按主体）

* 固定窗口算法，默认每主体 **10 次 / 10 秒**（`ztg.rate-limit-*` 可调）。
* 每个主体一个窗口对象，所有计数变更在
  `ConcurrentHashMap.compute` 内原子完成：高并发下**不会计数丢失，实际放行量绝不超过配额**。
* 请求若先占额度、后在重放阶段被拒（`NONCE_REPLAY` / `SEQUENCE_ROLLBACK`），
  引擎会调用 `release` **归还额度**，额度不会被失败请求永久占用。
* 限流以**归一主体**为维度：`svc-demo` 的 v1/v2 凭证共享配额，`svc-partner` 独立。

---

## 3. 重放防护策略

三重机制叠加：

1. **时间窗口**：`X-ZT-Timestamp` 与服务器时间偏差超过 `ztg.timestamp-window-seconds`（默认 30s）即拒，
   截获的旧请求无法重放；原因码 `STALE_TIMESTAMP`。
2. **nonce 唯一**：以主体为维度记录 TTL 内已使用的 nonce
   （`ztg.nonce-ttl-seconds`，默认 120s）。提交在 `compute` 内原子完成，
   **同一 nonce 并发提交恰好一次成功**，其余返回 `NONCE_REPLAY`，绝不静默通过。
   过期记录在该主体下一次请求时惰性清理。
3. **序号单调**：每个主体保存最新序号，请求序号必须严格递增，
   回退或相等返回 `SEQUENCE_ROLLBACK`（即便 nonce 不同也能识别）。

确定性：判定为纯函数式流程 + 原子状态提交，同一输入的判定结果稳定可复现
（见测试 `nonceReplayIsDetectedAndStable`、`concurrentSameRequestOnlyOneWins`）。

---

## 4. 本地验证方法

需要 JDK 21+ 与 Maven。

### 4.1 运行全部测试

```bash
mvn test
```

共 32 个用例（JUnit 5 + AssertJ + MockMvc），覆盖：

* `tests/security/SignatureVerifierTest`：V1/V2 同流程验签、跨密钥不可伪造、空体摘要确定性
* `tests/engine/DecisionEngineTest`：正常放行、全部 11 种拒绝原因、越权、篡改、
  nonce 重放与稳定性、序号回退、TTL 过期复用、限流串行边界、按主体隔离、
  **200 线程并发下限流器恰好放行配额**、**同一请求并发只通过一次**、重放拒绝归还配额
* `tests/web/ZeroTrustWebIntegrationTest`：真实 Spring 上下文 + MockMvc，
  断言 200/401/409/429 与响应体中的可区分原因码

每个用例均通过 SLF4J 打印输入（method/path/keyId/nonce/seq/body 长度）与判定依据
（`decision=ALLOW/DENY ... reason=... detail=...`），可在 surefire 输出或控制台查看。

### 4.2 启动应用并用 curl 手工验证

```bash
mvn spring-boot:run
# 另开终端（脚本内部用 openssl 3.x 计算头）：
scripts/local-sign.sh demo-key-v2 local-demo-secret-v2 HMAC-SHA256 svc-demo 1 '{"k":"v"}'
```

把同一条请求（相同 nonce + sequence）再发一次，将得到 `409 NONCE_REPLAY`；
连续发满 10 次后得到 `429 RATE_LIMITED`；不带任何 `X-ZT-*` 头得到 `401 MISSING_CREDENTIAL`。

---

## 5. 配置一览（`application.properties`）

```properties
ztg.timestamp-window-seconds=30   # 时间戳允许偏移
ztg.nonce-ttl-seconds=120         # nonce 保留时长
ztg.rate-limit-requests=10        # 每主体每窗口配额
ztg.rate-limit-window-seconds=10  # 窗口长度
ztg.credentials[n].*              # 本地凭证登记
```

## 6. 范围说明

* 限流计数与 nonce 记录为**进程内存态**，重启即清空；单机本地演示足够，
  不引入 Redis 等外部依赖（符合"全部状态本地完成"）。
* 密钥均为本地演示字符串，请勿在真实环境使用。
