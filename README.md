# Zero Trust Gateway (Java / Spring Boot)

在现有 Web 应用上实现的**本地可运行**零信任请求校验与限流能力：多来源凭证鉴权、
按调用主体的本地限流、防重放/防篡改判定。全部状态与密钥均在本地内存与配置文件中，
不依赖任何外部服务或真实凭证。

## 技术栈与构建

- Java 21+ / Spring Boot 3.4 / Maven
- 构建：`mvn compile`
- 测试：`mvn test`（25 个用例，覆盖正常、越权、重放、并发竞态、限流边界与 HTTP 端到端）
- 运行：`mvn spring-boot:run`，健康检查 `GET /healthz`，受保护演示接口 `POST /api/echo`

## 判定流水线

每个受保护请求（`/healthz`、`/error` 除外）依次经过：

```
必备头结构检查 -> 鉴权 -> 防重放/防篡改 -> 限流 -> 业务处理
```

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

### 鉴权拒绝原因（HTTP 401）

| 原因 | 含义 |
|------|------|
| `MISSING_CREDENTIAL` | 未携带凭证头 |
| `UNKNOWN_CREDENTIAL_TYPE` | 凭证类型前缀无法识别 |
| `MALFORMED_CREDENTIAL` | 必填字段缺失或 `expires` 非法 |
| `PRINCIPAL_MISMATCH` | 请求声明主体与凭证内嵌主体不一致 |
| `CREDENTIAL_EXPIRED` | 凭证已过 `expires` |
| `SIGNATURE_MISMATCH` | 密钥未知或签名与重算结果不符（含正文被篡改） |

## 限流规则

- 维度：调用主体（归一后的 `subjectId`），本地固定窗口计数。
- 配置：`zero-trust.gateway.quota-per-window`（默认 5）/ `zero-trust.gateway.window-millis`（默认 60000）。
- 并发语义：每主体独立锁，窗口判定与计数在同一临界区完成——
  高并发突发下实际放行量**恰好等于配额**，不丢计数；被拒绝的请求不消耗额度，
  额度不会被超限请求永久占用；窗口过期自动滚动恢复。
- 超限返回 HTTP 429 `RATE_LIMITED`，与鉴权（401）、重放（409）原因明确区分。

## 重放防护策略

- 每个请求必须携带唯一 `X-Request-Id` 与毫秒时间戳 `X-Timestamp`，可选单调序号 `X-Sequence`。
- 时间戳与本地时钟偏差超过 `zero-trust.gateway.timestamp-skew-millis`（默认 30000ms）即拒绝。
- 同一主体的 `requestId` 在有效期内只可使用一次；“查重 + 登记”在主体锁内原子完成，
  并发重放同一请求只会放行一次。
- `(timestamp, sequence)` 必须严格单调：时间回退或同时间戳下序号不增即拒绝。
- 只有通过全部检查的请求才登记 ID 并推进水位，被拒请求不污染状态。

| 原因 | HTTP | 含义 |
|------|------|------|
| `MISSING_REQUEST_ID` | 400 | 缺少唯一标识 |
| `MISSING_TIMESTAMP` | 400 | 缺少时间戳 |
| `TIMESTAMP_OUT_OF_WINDOW` | 409 | 时间戳超出允许偏差 |
| `REPLAYED_REQUEST` | 409 | requestId 重复提交 |
| `SEQUENCE_REGRESSION` | 409 | 时间戳/序号回退 |

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
```

## 测试覆盖

| 测试类 | 场景 |
|--------|------|
| `ZeroTrustGatewayTests` | 正常（v1/v2 归一）、缺失/未知/残缺凭证、伪造签名、正文篡改、过期、主体不一致、用错密钥、缺头、时间窗、重放、序号回退、判定稳定性、限流边界、拒绝不占额度 |
| `ZeroTrustConcurrencyTests` | 50 线程突发下放行量恰好等于配额；32 线程并发重放同一请求仅放行一次 |
| `GatewayHttpIntegrationTests` | 真实过滤器链：200/401/409/429 状态码与 JSON 原因码、健康检查旁路 |
