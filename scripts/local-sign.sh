#!/usr/bin/env bash
# 本地演示用：按网关规范计算 X-ZT-* 头并发起一次 /api/echo 请求。
# 依赖: openssl 3.x, curl
# 用法:
#   scripts/local-sign.sh <keyId> <secret> <HMAC-SHA1|HMAC-SHA256> <principal> <sequence> [body]
# 例（先 mvn spring-boot:run 启动应用）:
#   scripts/local-sign.sh demo-key-v2 local-demo-secret-v2 HMAC-SHA256 svc-demo 1 '{"k":"v"}'
set -euo pipefail

KEY_ID="${1:?keyId required}"
SECRET="${2:?secret required}"
ALGO="${3:-HMAC-SHA256}"
PRINCIPAL="${4:?principal required}"
SEQ="${5:?sequence required}"
BODY="${6:-}"

TS="$(date +%s)"
NONCE="local-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
BODY_HASH="$(printf '%s' "$BODY" | openssl dgst -sha256 -hex | awk '{print $2}')"

CANON="POST
/api/echo
${TS}
${NONCE}
${SEQ}
${BODY_HASH}"

DIGEST_NAME="$(echo "$ALGO" | tr '[:upper:]' '[:lower:]' | tr -d '-')"
SIGNATURE="$(printf '%s' "$CANON" | openssl dgst "-${DIGEST_NAME}" -mac HMAC -macopt "key:${SECRET}" | awk '{print $2}')"

echo "canonical string:"; printf '%s\n' "$CANON" | sed 's/^/  /'
echo "nonce=${NONCE}"

curl -sS -i -X POST http://localhost:8080/api/echo \
  -H 'Content-Type: text/plain' \
  -H "X-ZT-Key-Id: ${KEY_ID}" \
  -H "X-ZT-Principal: ${PRINCIPAL}" \
  -H "X-ZT-Timestamp: ${TS}" \
  -H "X-ZT-Nonce: ${NONCE}" \
  -H "X-ZT-Sequence: ${SEQ}" \
  -H "X-ZT-Body-Sha256: ${BODY_HASH}" \
  -H "X-ZT-Signature: ${SIGNATURE}" \
  --data-raw "$BODY"
echo
