#!/usr/bin/env bash
set -euo pipefail

# BFF (web-client) end-to-end smoke test: exercises the real browser flow
# through the web-client on :9084 — OAuth2 login redirect, auth-server login,
# the consent screen, the BFF callback, and the dashboard render.
# Requires: iam-server, auth-server, gateway, resource-server, web-client.

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

fail() { echo -e "${RED}FAIL${NC}: $*"; exit 1; }
pass() { echo -e "${GREEN}PASS${NC}: $*"; }

BFF="http://localhost:9084"
IAM="http://localhost:9083"
AUTH="http://localhost:9081"
COOKIES="$(mktemp)"
trap 'rm -f "$COOKIES"' EXIT

EMAIL="bffuser-$(date +%s)-$RANDOM@example.com"

echo "=== BFF (web-client) Smoke Test ==="
echo ""

# 0. Register a fresh end-user through IAM
curl -fsS -o /dev/null -X POST "$IAM/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"testpass123\"}" || fail "user registration"

# 1. Unauthenticated dashboard -> oauth2Login kickoff -> authorization server
echo "1. BFF start redirects to authorize"
KICKOFF=$(curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null -w "%{redirect_url}" "$BFF/") || fail "BFF root"
echo "$KICKOFF" | grep -q "oauth2/authorization/auth-platform" || fail "Expected oauth2Login kickoff, got $KICKOFF"
AUTHZ=$(curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null -w "%{redirect_url}" "$KICKOFF") || fail "authorize redirect"
echo "$AUTHZ" | grep -q "oauth2/authorize" || fail "Expected authorize redirect, got $AUTHZ"
echo "$AUTHZ" | grep -q "client_id=web-client" || fail "Expected web-client in authorize URL"
pass "BFF redirects to authorize (client_id=web-client)"

# 2. Login at the authorization server
echo "2. Login at the authorization server"
LOGIN_HTML=$(curl -fsS -c "$COOKIES" -b "$COOKIES" "$AUTH/login") || fail "login page"
CSRF=$(echo "$LOGIN_HTML" | grep -o 'name="_csrf" value="[^"]*"' | sed 's/.*value="//;s/"//')
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null -X POST "$AUTH/login" \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=testpass123" \
  --data-urlencode "user_type=USER" \
  --data-urlencode "_csrf=$CSRF" || fail "login POST"
pass "Logged in as $EMAIL"

# 3. Resume the authorize request -> consent screen
echo "3. Consent screen"
CONSENT_LOC=$(curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null -w "%{redirect_url}" "$AUTHZ") || fail "authorize resume"
echo "$CONSENT_LOC" | grep -q "oauth2/consent" || fail "Expected consent redirect, got $CONSENT_LOC"
CONSENT_HTML=$(curl -fsS -c "$COOKIES" -b "$COOKIES" "$CONSENT_LOC") || fail "consent page"
CSTATE=$(echo "$CONSENT_HTML" | grep -o 'name="state" value="[^"]*"' | sed 's/.*value="//;s/"//' | python3 -c "import sys,html; print(html.unescape(sys.stdin.read().strip()))")
pass "Consent page reached"

# 4. Approve the scopes
echo "4. Approve consent"
CALLBACK=$(curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null -w "%{redirect_url}" -X POST "$AUTH/oauth2/authorize" \
  --data-urlencode "client_id=web-client" \
  --data-urlencode "state=$CSTATE" \
  --data-urlencode "scope=openid" --data-urlencode "scope=profile" \
  --data-urlencode "scope=read" --data-urlencode "scope=write") || fail "consent POST"
echo "$CALLBACK" | grep -q "login/oauth2/code/auth-platform" || fail "Expected BFF callback, got $CALLBACK"
pass "Consent approved -> BFF callback"

# 5. Follow the BFF callback -> dashboard renders with the user's email
echo "5. Dashboard renders"
DASH=$(curl -fsSL -c "$COOKIES" -b "$COOKIES" -w "\n%{http_code}" "$CALLBACK") || fail "dashboard fetch"
DASH_BODY=$(echo "$DASH" | head -n -1)
echo "$DASH_BODY" | grep -q "$EMAIL" || fail "Dashboard does not show $EMAIL"
pass "Dashboard rendered (email visible)"

echo ""
echo -e "${GREEN}BFF smoke tests passed.${NC}"
