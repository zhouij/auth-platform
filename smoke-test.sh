#!/usr/bin/env bash
set -euo pipefail

# Auth Gateway System — End-to-End Smoke Test
# Run after: docker compose up --build -d
# Prerequisites: jq installed

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

fail() { echo -e "${RED}FAIL${NC}: $*"; exit 1; }
pass() { echo -e "${GREEN}PASS${NC}: $*"; }

AUTH_SERVER="http://localhost:9081"
GATEWAY="http://localhost:9080"
IAM_SERVER="http://localhost:9083"

echo "=== Auth Gateway Smoke Test ==="
echo ""

# 1. Auth Server — OIDC Discovery
echo "1. OIDC Discovery"
DISCO=$(curl -fsS "$AUTH_SERVER/.well-known/openid-configuration" 2>/dev/null) || fail "OIDC discovery"
ISSUER=$(echo "$DISCO" | jq -r .issuer)
[ "$ISSUER" = "$AUTH_SERVER" ] || fail "Issuer: expected $AUTH_SERVER, got $ISSUER"
pass "OIDC discovery (issuer=$ISSUER)"

# 2. Auth Server — JWKS
echo "2. JWKS Endpoint"
JWKS=$(curl -fsS "$AUTH_SERVER/oauth2/jwks" 2>/dev/null) || fail "JWKS endpoint"
KEYS=$(echo "$JWKS" | jq '.keys | length')
[ "$KEYS" -ge 1 ] || fail "JWKS: expected at least 1 key"
pass "JWKS ($KEYS key(s))"

# 3. Auth Server — client_credentials token
echo "3. Client Credentials Token"
TOKEN_RESPONSE=$(curl -fsS -X POST "$AUTH_SERVER/oauth2/token" \
  -u "service-client:service-secret" \
  -d "grant_type=client_credentials&scope=read" 2>/dev/null) || fail "Token endpoint"
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)
[ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ] || fail "Access token not found"
TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | jq -r .token_type)
[ "$TOKEN_TYPE" = "Bearer" ] || fail "Token type: expected Bearer, got $TOKEN_TYPE"
pass "Token issued (type=$TOKEN_TYPE, scope=read)"

# 4. Gateway — public endpoint (no auth)
echo "4. Gateway Public Endpoint"
PUBLIC=$(curl -fsS "$GATEWAY/api/v1/public/status" 2>/dev/null) || fail "Public endpoint"
STATUS=$(echo "$PUBLIC" | jq -r .status)
[ "$STATUS" = "ok" ] || fail "Public status: expected ok, got $STATUS"
pass "Public endpoint accessible without token"

# 5. Gateway — authenticated endpoint (with token)
echo "5. Gateway Authenticated Endpoint"
WHOAMI=$(curl -fsS -H "Authorization: Bearer $ACCESS_TOKEN" "$GATEWAY/api/v1/whoami" 2>/dev/null) || fail "WhoAmI endpoint"
SUB=$(echo "$WHOAMI" | jq -r .subject)
[ -n "$SUB" ] && [ "$SUB" != "null" ] || fail "Subject not found in whoami"
pass "Authenticated endpoint (sub=$SUB)"

# 6. Gateway — protected endpoint without token (expect 401)
echo "6. Gateway — No Token (expect 401)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY/api/v1/resources" 2>/dev/null)
[ "$HTTP_CODE" = "401" ] || fail "Expected 401 without token, got $HTTP_CODE"
pass "401 without token"

# 7. IAM Server — register user
echo "7. IAM User Registration"
REG=$(curl -fsS -X POST "$IAM_SERVER/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"smoketest@example.com","password":"testpass123","firstName":"Smoke","lastName":"Test"}' 2>/dev/null) || fail "User registration"
USER_ID=$(echo "$REG" | jq -r .userId)
[ -n "$USER_ID" ] && [ "$USER_ID" != "null" ] || fail "User ID not returned"
pass "User registered (id=$USER_ID)"

# 8. IAM Server — login
echo "8. IAM Login"
LOGIN=$(curl -fsS -X POST "$IAM_SERVER/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"smoketest@example.com","password":"testpass123"}' 2>/dev/null) || fail "Login endpoint"
LOGIN_TYPE=$(echo "$LOGIN" | jq -r .userType)
[ "$LOGIN_TYPE" = "USER" ] || fail "User type: expected USER, got $LOGIN_TYPE"
pass "Login successful (type=$LOGIN_TYPE)"

# 9. IAM Server — login with wrong password (expect 401)
echo "9. IAM Login — Wrong Password (expect 401)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$IAM_SERVER/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"smoketest@example.com","password":"wrongpass"}' 2>/dev/null)
[ "$HTTP_CODE" = "401" ] || fail "Expected 401 with wrong password, got $HTTP_CODE"
pass "401 with wrong password"

# 10. IAM Server — duplicate registration (expect 409)
echo "10. IAM — Duplicate Registration (expect 409)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$IAM_SERVER/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"smoketest@example.com","password":"testpass123"}' 2>/dev/null)
[ "$HTTP_CODE" = "409" ] || fail "Expected 409 for duplicate email, got $HTTP_CODE"
pass "409 for duplicate registration"

# 11. Auth Server — internal revoke endpoint (protected)
echo "11. Internal Revoke — Invalid Token (expect 401)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$AUTH_SERVER/internal/auth/revoke-user/some-id" \
  -H "X-Internal-Token: wrong-token" 2>/dev/null)
[ "$HTTP_CODE" = "401" ] || fail "Expected 401 for invalid internal token, got $HTTP_CODE"
pass "401 for invalid internal token"

# 12. Resource Server — admin endpoint with USER token (expect 403)
echo "12. Resource Server — Admin endpoint with USER token (expect 403)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $ACCESS_TOKEN" "$GATEWAY/api/v1/admin/resources" 2>/dev/null)
[ "$HTTP_CODE" = "403" ] || fail "Expected 403 for USER token on admin endpoint, got $HTTP_CODE"
pass "403 for USER token on admin endpoint"

echo ""
echo -e "${GREEN}All smoke tests passed.${NC}"
