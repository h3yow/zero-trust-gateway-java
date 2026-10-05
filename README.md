# Zero Trust Gateway (Java / Spring Boot)

在现有 Web 应用上实现的**本地可运行**零信任请求校验与限流能力：多来源凭证鉴权、
按调用主体的本地限流、防重放/防篡改判定。全部状态与密钥均在本地内存与配置文件中，
不依赖任何外部服务或真实凭证。

## 技术栈与构建

- Java 21+ / Spring Boot 3.4 / Maven
- 构建：`mvn compile`
- 测试：`mvn test`（40 个用例，覆盖正常、越权、凭证生命周期、重放时效/容量收敛、
  被拒后重试与并发交错、限流/重放混合突发、限流边界与 HTTP 端到端）
- 运行：`mvn spring-boot:run`，健康检查 `GET /healthz`，受保护演示接口 `POST /api/echo`

## 判定流水线

每个受保护请求（`/healthz`、`/error` 除外）依次经过：

```
必备头结构检查 -> 鉴权(含服务端生命周期)
  -> [每主体锁内原子] 防重放只读预检 -> 限流占配额 -> 防重放复检+登记提交
  -> 业务处理
```

**并发下的准入原子性**：鉴权通过之后，“只读预检 -> 占配额 -> 登记提交”三步在
**每个调用主体一把锁**内原子完成，同一主体的并发请求被串行化判定：

- **重放预检先于限流**：窗口内重复、序号回退、容量满在预检阶段直接定案，
  重复请求**全程不触碰配额**——即使配额已满也稳定判 `REPLAYED_REQUEST`，
  不会被超限原因盖掉，也不会在“占用→归还”之间临时挤掉本该放行的新请求。
- **只有预检通过的全新请求才参与配额竞争**：配额之内、窗口内无重复的请求必然放行，
  不会被同时涌入的大量重复请求牵连成超限。
- 被限流的请求不真正执行，因此既不登记 `requestId`、也不推进序号水位——
  配额恢复后调用方拿**同一个请求**（相同 `X-Request-Id` / `X-Sequence`）重试可被正常处理，
  不会被误判为重放或序号回退；通过限流但在登记复检时被拒的请求会归还刚占用的配额。

任一环节失败即返回可区分的拒绝原因（JSON：`{"allowed":false,"reason":"...","message":"..."}`），
输入要素与判定依据均打印在应用日志中（`收到判定输入` / `判定依据`），同一输入在状态一致时结论稳定可复现。

## 凭证兼容范围

同一套判定流程兼容两种 HMAC 凭证版本，差异仅在签名编码：

| 版本 | 签名算法 | 签名编码 |
|------|----------|----------|
| `HMAC1` (v1) | HmacSHA256 | 小写 hex |
| `HMAC2` (v2) | HmacSHA256 | Base64 |

凭证头（放在 `Authorization`）：

```
HMAC1 keyId=alice;subject=alice;expires=1790000000000;sig=<hex|base64>
```

签名原文（`\n` 连接）绑定凭证字段与全部请求要素，因此签名同时承担防篡改：

```
<version>\n<subject>\n<subject>\n<expires>\n<method>\n<path>\n<requestId>\n<timestamp>\n<sequence>\n<bodySha256>
```

- 正文 SHA-256 由服务端计算（Base64），客户端需按同一规则计算后参与签名；正文被篡改即签名不符。
- 本地密钥在 `application.properties` 的 `zero-trust.gateway.credentials` 中登记
  （`subjectId:base64(密钥)`，逗号分隔），内置 `alice`、`bob` 两个测试主体。

### 服务端凭证生命周期（生效时间 / 失效时间 / 撤销）

每个调用主体的凭证生命周期在**服务端本地集中登记**，判定一律以本地登记为准：
即使客户端凭证头自带的 `expires` 或状态看起来仍有效，只要本地登记显示未生效、已失效或已撤销，就必须拒绝。
HMAC1 与 HMAC2 走同一套判定，撤销优先于时间窗口、优先于签名校验。

配置在密钥后追加可选的生命周期段（冒号分段，均可留空），不带该段的旧配置完全兼容，表示“已登记、无时间限制”：

```
# subjectId : base64(密钥) : notBeforeMillis : notAfterMillis : revoked
zero-trust.gateway.credentials=carol:Y2Fyb2wtbG9jYWwtc2VjcmV0:1700000000000:1800000000000:false,dave:ZGF2ZS1sb2NhbC1zZWNyZXQ::::true
```

- `notBeforeMillis` / `notAfterMillis`：epoch 毫秒，留空表示不设限；当前时刻早于 `notBefore`
  判 `CREDENTIAL_NOT_YET_VALID`，晚于 `notAfter` 判 `CREDENTIAL_EXPIRED`。
- `revoked`：`true`/`false`（默认 `false`），为 `true` 判 `CREDENTIAL_REVOKED`。
- 运行期可随时撤销 / 重新发放（本地内存即生效，无需重启）：
  `LocalCredentialRegistry#revoke(subjectId)` 立即撤销；
  `LocalCredentialRegistry#register(subjectId, key, new CredentialLifecycle(notBefore, notAfter, revoked))`
  覆盖登记（撤销后重新发放凭证）。
- 兼容范围：旧的两段式 `subjectId:key` 配置继续可用；两类 HMAC 凭证版本对生命周期判定无差异；
  凭证头自带的 `expires` 仍会校验，但**不能推翻**本地登记的结论。

### 鉴权拒绝原因（HTTP 401）

| 原因 | 含义 |
|------|------|
| `MISSING_CREDENTIAL` | 未携带凭证头 |
| `UNKNOWN_CREDENTIAL_TYPE` | 凭证类型前缀无法识别 |
| `MALFORMED_CREDENTIAL` | 必填字段缺失或 `expires` 非法 |
| `PRINCIPAL_MISMATCH` | 请求声明主体与凭证内嵌主体不一致 |
| `CREDENTIAL_NOT_YET_VALID` | 本地登记的生效时间未到（以服务端为准） |
| `CREDENTIAL_EXPIRED` | 本地登记已失效，或凭证头 `expires` 已过 |
| `CREDENTIAL_REVOKED` | 主体凭证已被服务端撤销（撤销优先于签名） |
| `SIGNATURE_MISMATCH` | 密钥未知或签名与重算结果不符（含正文被篡改） |

## 限流规则

- 维度：调用主体（归一后的 `subjectId`），本地固定窗口计数。
- 配置：`zero-trust.gateway.quota-per-window`（默认 5）/ `zero-trust.gateway.window-millis`（默认 60000）。
- 并发语义：每主体独立锁，窗口判定与计数在同一临界区完成——
  高并发突发下实际放行量**恰好等于配额**，不丢计数；被拒绝的请求不消耗额度，
  额度不会被超限请求永久占用；窗口过期自动滚动恢复。
- **与重放拒绝的区分**：重复/重放请求在占用配额之前的只读预检中即被判出，
  因此它**既不占用、也不临时借用配额**；配额被打满时，重复请求仍然返回 409
  `REPLAYED_REQUEST` 而不是 429，同一请求的拒绝原因不会在两者间抖动。
  反过来，429 只发给“预检通过的全新请求真正遇到配额耗尽”的情形。
- 超限返回 HTTP 429 `RATE_LIMITED`，与鉴权（401）、重放（409）原因明确区分。

## 重放防护策略：时效收敛 + 容量收敛

- 每个请求必须携带唯一 `X-Request-Id` 与毫秒时间戳 `X-Timestamp`，可选单调序号 `X-Sequence`。
- 时间戳与本地时钟偏差超过 `zero-trust.gateway.timestamp-skew-millis`（默认 30000ms）即拒绝。
- **时效收敛**：同一主体的 `requestId` 只在“该请求自身的时间窗口”内占用，记录过期点为
  `请求timestamp + skew`（而非登记时刻）。到达期后陈旧记录在下次判定时被摊销清理（O(1) 到期队列 +
  O(1) 哈希查重），不再拦截之后携带同一标识的新请求；长期高吞吐、标识持续变化时，
  保留规模只覆盖约一个时间窗口，不会只增不减，判定耗时稳定。
- **窗口内重放一律拦截**：清理过期记录后仍在哈希表中的标识判 `REPLAYED_REQUEST`；
  “到期清理 + 查重 + 容量判定 + 登记”在每主体独立锁内原子完成，并发下不误判、不漏判。
- **容量收敛**：每主体有效记录数受 `zero-trust.gateway.replay-max-ids-per-subject`（默认 10000）约束。
  达到上限时**先清理过期记录**；清理后仍满，新的（非重复）请求被明确拒绝为
  `REPLAY_STORE_FULL`（HTTP 503，带 `Retry-After`）——不静默放过，也不淘汰仍在有效期内的重复记录。
  窗口内真正的重复请求即使容量已满，仍判 `REPLAYED_REQUEST`（重放判定优先于容量拒绝）。
- `(timestamp, sequence)` 必须严格单调：时间回退或同时间戳下序号不增即拒绝。
- **预检/提交两阶段**：`inspect`（只读预检，不登记、不推进水位）与 `check`
  （原子复检+登记）判定口径一致。网关编排把预检放在限流之前、登记放在拿到配额之后，
  三步同处每主体锁内——重复请求永远不碰配额，被拒请求也不会留下任何去重痕迹。
- 只有鉴权通过、拿到配额且通过防重放、真正会被执行的请求才登记 ID 并推进水位；
  鉴权失败、要素缺失与限流被拒的请求都不会进入防重放状态。

| 原因 | HTTP | 含义 |
|------|------|------|
| `MISSING_REQUEST_ID` | 400 | 缺少唯一标识 |
| `MISSING_TIMESTAMP` | 400 | 缺少时间戳 |
| `TIMESTAMP_OUT_OF_WINDOW` | 409 | 时间戳超出允许偏差 |
| `REPLAYED_REQUEST` | 409 | 窗口内 requestId 重复提交（容量满或配额满时，重复仍判此原因） |
| `SEQUENCE_REGRESSION` | 409 | 时间戳/序号回退 |
| `REPLAY_STORE_FULL` | 503 | 清完过期记录后有效记录仍达容量上限，带 `Retry-After` |

## 被拒之后重试的行为

- 调用方配额打满被拒（429）后，等待配额恢复，拿**同一个请求**（相同 `X-Request-Id` 与 `X-Sequence`，
  时间戳仍需落在偏差窗口内、签名要素不变）重试，会被正常处理，不会因上一轮被拒而被判
  `REPLAYED_REQUEST` 或 `SEQUENCE_REGRESSION`。
- 鉴权失败（如签名不符）的请求不占去重名额：修正签名后用同一 `requestId` 重新提交可以放行。
- 限流被拒的请求不推进该主体的序号水位；通过限流但被防重放拒绝的请求会归还已占用的配额。
- 并发语义：配额已满时同一请求的并发重试**全部**得到 429 且不留任何去重痕迹；
  配额恢复后的并发重试恰好执行一次，其余得到 409 `REPLAYED_REQUEST`，该拒的拒、该放的放。
- **并发下两种拒绝的区分**：窗口内重复请求即使赶上配额打满，也稳定判 409
  `REPLAYED_REQUEST`（重放预检优先于限流），原因不会在 409/429 间抖动；
  全新请求只要配额之内、窗口内无重复就必然放行，不会被同时突发的重复请求挤成 429。

## 本地验证方法

```bash
# 1. 全量测试（含并发竞态与 HTTP 端到端，日志中可见输入与判定依据）
mvn test

# 2. 启动本地服务
mvn spring-boot:run

# 3. 手工构造一个合法请求（以 alice、HMAC1 为例）
SUB=alice
KEY_B64=$(grep '^zero-trust.gateway.credentials' src/main/resources/application.properties \
          | cut -d= -f2 | cut -d, -f1 | cut -d: -f2)
RID=$(cat /proc/sys/kernel/random/uuid)
TS=$(date +%s%3N)
SEQ=1
EXPIRES=$((TS + 600000))
BODY='{"hello":"world"}'
BODY_SHA=$(printf '%s' "$BODY" | openssl dgst -sha256 -binary | base64)
CANONICAL=$(printf 'HMAC1\n%s\n%s\n%s\nPOST\n/api/echo\n%s\n%s\n%s\n%s' \
            "$SUB" "$SUB" "$EXPIRES" "$RID" "$TS" "$SEQ" "$BODY_SHA")
SIG=$(printf '%s' "$CANONICAL" | openssl dgst -sha256 -hmac "$(echo "$KEY_B64" | base64 -d)" -hex | awk '{print $2}')

curl -i -X POST http://localhost:8080/api/echo \
  -H "Content-Type: application/json" \
  -H "Authorization: HMAC1 keyId=$SUB;subject=$SUB;expires=$EXPIRES;sig=$SIG" \
  -H "X-Request-Id: $RID" -H "X-Timestamp: $TS" -H "X-Sequence: $SEQ" \
  -d "$BODY"

# 4. 再发一次完全相同的请求 -> 409 REPLAYED_REQUEST；去掉 Authorization -> 401 MISSING_CREDENTIAL

# 5. 被拒后重试（先打满配额再重试同一请求）
#    连续发 5 个合法请求打满 alice 的配额，第 6 个请求会得到 429 RATE_LIMITED；
#    等窗口滚动（默认 60s，或重启服务）后，用“同一个 X-Request-Id / X-Sequence”再发一次 -> 200。
#    （自动化验证见 RetryAfterRejectionTests，无需手工等待窗口。）

# 6. 服务端撤销（可用 curl 前在代码/测试中调用 LocalCredentialRegistry#revoke("alice")，
#    或在 application.properties 的该主体生命周期段把 revoked 置为 true 后重启）
#    撤销后即使凭证头 expires 是未来、签名正确，也返回 401 CREDENTIAL_REVOKED。
```

### 用自动化测试验证新场景（无需等待真实窗口）

```bash
# 服务端生命周期：有效/未生效/失效/撤销，HMAC1 与 HMAC2 一致，原因与签名不符可区分
mvn test -Dtest=CredentialLifecycleTests

# 重放记录时效边界（过期点精确到毫秒）与容量收敛（容量满 -> REPLAY_STORE_FULL，过期后恢复）
mvn test -Dtest=ReplayConvergenceTests

# 被拒后重试：限流重试、鉴权失败不占名额、配额归还、并发限流/重试交错
mvn test -Dtest=RetryAfterRejectionTests

# 并发竞态：限流突发、并发重放仅放行一次、全新/重复混合突发（全新全放行、重复全判重放）
mvn test -Dtest=ZeroTrustConcurrencyTests

# 全量回归（40 个用例）；日志中搜索“判定依据 / 收敛判定依据 / 重试判定依据 / 混合突发”可看到每个场景的判定理由
mvn test
```

## 测试覆盖

| 测试类 | 场景 |
|--------|------|
| `ZeroTrustGatewayTests` | 正常（v1/v2 归一）、缺失/未知/残缺凭证、伪造签名、正文篡改、过期、主体不一致、用错密钥、缺头、时间窗、重放、序号回退、判定稳定性、限流边界、拒绝不占额度 |
| `CredentialLifecycleTests` | 本地登记有效（v1/v2 一致）、本地失效压过凭证头 expires、未生效、运行期撤销立即生效并可重新登记恢复、撤销优先于签名、撤销与签名不符原因可区分且主体间互不影响 |
| `ReplayConvergenceTests` | 可控时钟下的时效边界（窗口内拦截、恰过窗口清理后同 id 放行）、万级唯一标识流入下记录摊销清理且规模有界（~1 窗口）、容量满明确 `REPLAY_STORE_FULL` 且过期恢复、容量满时真重复仍判重放 |
| `RetryAfterRejectionTests` | 限流被拒的同一请求恢复后重试放行、鉴权失败不占去重名额、防重放拒绝归还配额、并发下“限流全拒不留痕→恢复后恰好放行一次”两阶段交错 |
| `ZeroTrustConcurrencyTests` | 50 线程突发下放行量恰好等于配额；32 线程并发重放同一请求仅放行一次；5 个全新请求与 60 个“已处理过的同一重复请求”混合突发——全新全部放行、重复全部判 `REPLAYED_REQUEST`（无 429 抖动）、放行数不超配额 |
| `GatewayHttpIntegrationTests` | 真实过滤器链：200/401/409/429 状态码与 JSON 原因码、健康检查旁路 |
