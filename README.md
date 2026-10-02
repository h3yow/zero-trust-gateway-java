# Zero Trust Gateway (Java / Spring Boot)

在现有 Web 应用上实现的**本地可运行**零信任请求校验与限流能力：多来源凭证鉴权、
按调用主体的本地限流、防重放/防篡改判定。全部状态与密钥均在本地内存与配置文件中，
不依赖任何外部服务或真实凭证。

## 技术栈与构建

- Java 21+ / Spring Boot 3.4 / Maven
- 构建：`mvn compile`
- 测试：`mvn test`（45 个用例，覆盖正常、越权、服务端凭证生命周期、重放时效与容量收敛、
  被拒后重试、并发竞态、限流边界与 HTTP 端到端）
- 运行：`mvn spring-boot:run`，健康检查 `GET /healthz`，受保护演示接口 `POST /api/echo`

## 判定流水线

每个受保护请求（`/healthz`、`/error` 除外）依次经过：

```
必备头结构检查 -> 鉴权（含服务端凭证生命周期）
  -> 防重放/防篡改检查（只读，不留痕）
  -> 限流占额 -> 去重登记 -> 业务处理
```

任一环节失败即返回可区分的拒绝原因（JSON：`{"allowed":false,"reason":"...","message":"..."}`），
输入要素与判定依据均打印在应用日志中（`收到判定输入` / `判定依据` / `生命周期拒绝` /
`重放记录时效收敛`），同一输入在状态一致时结论稳定可复现。

**检查与登记分离（被拒后可安全重试）**：鉴权失败与防重放拒绝发生在限流占额之前，
限流拒绝发生在去重登记之前——三类拒绝都既不占用去重名额、也不推进序号水位、也不真正计费；
占额后若在登记阶段因极端并发被抢先，会原样退还配额。因此调用方配额恢复后拿同一请求
（同一 `requestId` 与序号，按当前时间重新签名）重试，会被正常处理，而不会被当成
重复请求或序号回退。

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

## 服务端凭证生命周期（集中登记，本地为准）

凭证生效时间、失效时间与撤销状态由**服务端本地集中登记**，两类凭证版本
（HMAC1/HMAC2）归一到同一 `subjectId` 后走同一套判定。判断一律以本地登记为准：
哪怕客户端请求头里的 `expires` 看起来仍有效，只要本地登记显示该主体尚未生效、
已经失效或被撤销，就必须拒绝。

### 配置方式

`zero-trust.gateway.credential-lifecycles`（逗号分隔，可选）：

```properties
# 只在 [notBefore, notAfter] 毫秒时间戳区间内有效
zero-trust.gateway.credential-lifecycles=charlie:1759400000000:1790000000000
# notBefore 留空 = 该边界不限制（仅设失效时间）
zero-trust.gateway.credential-lifecycles=erin::1759000000000
# 启动即撤销
zero-trust.gateway.credential-lifecycles=dave:revoked
# 多条组合
zero-trust.gateway.credential-lifecycles=charlie:1759400000000:1790000000000,erin::1759000000000,dave:revoked
```

- 字段顺序固定为 `subject:notBefore:notAfter`，时间均为 epoch 毫秒，边界留空表示不限制。
- 运行时随时撤销：注入 `CredentialLifecycleManager` 调用 `revoke(subjectId)`，立即生效。
- **兼容范围**：该配置为可选项。未登记生命周期的主体（如内置 `alice`/`bob`）行为与
  旧版本完全一致，仍只校验凭证头自带的 `expires`；登记了生命周期的主体则本地判定优先。
- 生命周期判定位于“主体已在本地登记密钥”之后、签名校验之前；生命周期拒绝与
  “签名不符 / 主体不一致”原因彼此可区分。

### 鉴权拒绝原因（HTTP 401）

| 原因 | 含义 |
|------|------|
| `MISSING_CREDENTIAL` | 未携带凭证头 |
| `UNKNOWN_CREDENTIAL_TYPE` | 凭证类型前缀无法识别 |
| `MALFORMED_CREDENTIAL` | 必填字段缺失或 `expires` 非法 |
| `PRINCIPAL_MISMATCH` | 请求声明主体与凭证内嵌主体不一致 |
| `CREDENTIAL_NOT_YET_VALID` | 本地登记的生效时间（notBefore）尚未到，凭证头再“新”也拒绝 |
| `CREDENTIAL_EXPIRED` | 本地登记已失效（notAfter），或凭证头自带 `expires` 已过；消息注明判定来源 |
| `CREDENTIAL_REVOKED` | 本地登记（配置或运行时 `revoke`）已撤销该主体 |
| `SIGNATURE_MISMATCH` | 密钥未知或签名与重算结果不符（含正文被篡改） |

## 限流规则

- 维度：调用主体（归一后的 `subjectId`），本地固定窗口计数。
- 配置：`zero-trust.gateway.quota-per-window`（默认 5）/ `zero-trust.gateway.window-millis`（默认 60000）。
- 并发语义：每主体独立锁，窗口判定与计数在同一临界区完成——
  高并发突发下实际放行量**恰好等于配额**，不丢计数；被拒绝的请求不消耗额度，
  额度不会被超限请求永久占用；窗口过期自动滚动恢复。
- 限流位于鉴权与防重放只读检查之后、去重登记之前：被限流的请求不占去重名额、不推进序号水位，
  因此配额恢复后可用同一 requestId/序号重试成功（详见“被拒之后重试的行为”）。
- 超限返回 HTTP 429 `RATE_LIMITED`，与鉴权（401）、重放（409）、容量保护（503）原因明确区分。

## 重放防护策略：时效与容量收敛

- 每个请求必须携带唯一 `X-Request-Id` 与毫秒时间戳 `X-Timestamp`，可选单调序号 `X-Sequence`。
- 时间戳与本地时钟偏差超过 `zero-trust.gateway.timestamp-skew-millis`（默认 30000ms）即拒绝。
- 同一主体的 `requestId` 只在对应时间窗口（请求 `timestamp + skew`）内占用。越过窗口后的
  陈旧记录会在后续判定时由**最小过期堆**即时回收，回收后同一 requestId 可作为新请求再次使用，
  不会再被旧记录拦截。
- 记录规模**按时效收敛、只减不增**：每个条目一生只入堆/出堆各一次，过期回收入口只看堆顶
  （O(1)），查重为 O(1) 哈希，不做全表扫描；长期高吞吐、大量互不相同的 requestId 持续进来时，
  单次判定耗时保持稳定。
- 窗口内的重放一律拦截；“过期回收 + 查重 + 水位比较”在每主体独立锁的同一临界区内原子完成，
  并发下不误判（重复双放行）也不漏判。
- **容量上限 fail-closed**：每主体有效记录数受
  `zero-trust.gateway.replay-max-records-per-subject`（默认 100000）硬约束。达到上限时先回收
  过期记录；回收后仍无空位则返回 `REPLAY_CAPACITY_EXCEEDED`——明确拒绝（HTTP 503），
  绝不静默放过，也绝不驱逐任何仍在有效期内的记录（因此满容量时窗口内重复仍稳定识别为重放）。
  一旦时间推进使旧记录过期，新请求立即恢复放行。
- `(timestamp, sequence)` 必须严格单调：时间回退或同时间戳下序号不增即拒绝。
- 只有真正将被放行的请求才在 `commit` 阶段登记 ID 并推进水位；鉴权失败、重放拒绝、
  限流拒绝都不污染状态。

| 原因 | HTTP | 含义 |
|------|------|------|
| `MISSING_REQUEST_ID` | 400 | 缺少唯一标识 |
| `MISSING_TIMESTAMP` | 400 | 缺少时间戳 |
| `TIMESTAMP_OUT_OF_WINDOW` | 409 | 时间戳超出允许偏差 |
| `REPLAYED_REQUEST` | 409 | 窗口内 requestId 重复提交 |
| `SEQUENCE_REGRESSION` | 409 | 时间戳/序号回退 |
| `REPLAY_CAPACITY_EXCEEDED` | 503 | 有效重放记录达上限且无过期可回收（fail-closed，结果可解释） |

## 被拒之后重试的行为

- 鉴权失败（签名不符、主体不一致、生命周期未生效/已失效/已撤销等）：发生在任何状态登记之前，
  不占去重名额、不推进序号水位、不计费。
- 防重放/防篡改拒绝（时间窗外、窗口内重放、序号回退、容量保护）：`check` 为只读判定，
  不留痕、不占额。
- 限流拒绝（`RATE_LIMITED`）：发生在去重登记之前，被拒请求不消耗去重名额、不推进序号水位。
- **配额恢复后的重试**：调用方等待限流窗口滚动后，拿“同一个请求”（同一 `X-Request-Id`
  与 `X-Sequence`；因限流窗口通常长于时间戳偏差窗口，需用**当前时间戳重新生成签名**）重发，
  网关会正常处理，而不会因上一轮被拒就判为 `REPLAYED_REQUEST` 或 `SEQUENCE_REGRESSION`。
- 并发语义：旧窗口内对同一请求的并发突发全部限流（无一登记）；窗口滚动后的并发重试中
  恰好一次成功，其余全部识别为窗口内重放——该拒的不漏、该放的不误拒。

## 本地验证方法

```bash
# 1. 全量测试（45 个用例：生命周期、时效/容量收敛、被拒后重试、并发竞态、HTTP 端到端；
#    日志中可见每个场景的输入与判定依据，关键标记：
#    “生命周期拒绝 / 重放记录时效收敛 / 重放容量保护拒绝 / 限流拒绝…可在配额恢复后重试”）
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
```

### 新场景本地验证要点

- **服务端生命周期**：在 `application.properties` 设置
  `zero-trust.gateway.credential-lifecycles=<subject>::$(($(date +%s%3N)-60000))`（失效时间设为
  1 分钟前），重启后即使凭证头 `expires` 是未来时间，请求仍返回 401 `CREDENTIAL_EXPIRED`；
  改为 `<subject>:revoked` 返回 401 `CREDENTIAL_REVOKED`；删除该配置即恢复（验证兼容范围）。
- **被拒后重试**：配额为 5，连发 6 个请求，第 6 个得到 429 `RATE_LIMITED`；等待窗口滚动
  （`window-millis`）后，用**同一 `X-Request-Id`/`X-Sequence` 与当前时间戳重新签名**重发，
  返回 200，而不是 409。
- **时效/容量收敛**：相关边界用 `CredentialLifecycleTests` / `ReplayConvergenceTests` /
  `RetryAfterRejectionTests` 中的可控时钟确定性覆盖（无需真实等待窗口），直接运行
  `mvn test -Dtest=ReplayConvergenceTests,RetryAfterRejectionTests,CredentialLifecycleTests`
  即可，并在日志中观察 `重放记录时效收敛`、`重放容量保护拒绝` 等判定依据。

## 测试覆盖

| 测试类 | 场景 |
|--------|------|
| `ZeroTrustGatewayTests` | 正常（v1/v2 归一）、缺失/未知/残缺凭证、伪造签名、正文篡改、过期、主体不一致、用错密钥、缺头、时间窗、重放、序号回退、判定稳定性、限流边界、拒绝不占额度（既有，无回归） |
| `CredentialLifecycleTests` | 服务端生命周期：窗口内有效（v1/v2 一致）、未登记主体兼容、未生效、已失效、本地登记覆盖客户端 expires、运行时撤销、配置撤销、撤销与签名原因可区分 |
| `ReplayConvergenceTests` | 窗口内重放必拦、精确到毫秒的到期边界（到期前/当刻拦截、越过即放行）、越过窗口陈旧记录可复用、500 个高吞吐请求下记录规模按时效收敛且不超上限、容量上限 fail-closed、过期后自动恢复、满容量时窗口内重放仍被识别 |
| `RetryAfterRejectionTests` | 限流后同请求配额恢复重试成功、限流不推进序号水位、鉴权失败不留痕、时间窗拒绝不占名额、旧窗口并发全限流 + 恢复后并发重试恰好一次成功其余判重放 |
| `ZeroTrustConcurrencyTests` | 50 线程突发下放行量恰好等于配额；32 线程并发重放同一请求仅放行一次（既有，无回归） |
| `GatewayHttpIntegrationTests` | 真实过滤器链：200/401/409/429 状态码与 JSON 原因码、健康检查旁路（既有，无回归） |
