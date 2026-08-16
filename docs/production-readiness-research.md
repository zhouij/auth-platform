# Production Readiness Research — Auth Platform

> Research snapshot saved 2026-08-15. The goal of this document is to let a
> fresh session (or a new teammate) pick up exactly where the analysis ended.

## TL;DR

The platform (Kotlin / Spring Boot 4.0.6 / Spring Security 7.0.5) was
functionally broken for production after the "upgrade everything" commit.
All critical defects were diagnosed empirically against the running stack,
fixed in **PR #2** (`fix/boot4-security7-production-readiness`,
commit `0aa10fe`, merged as `fbca5e4` on `main`), and the remaining work is
itemized below in priority order.

- Project: https://github.com/zhouij/auth-platform
- PR with the fixes: https://github.com/zhouij/auth-platform/pull/2

---

## 1. What the project is

Five-service auth platform:

| Service | Port | DB | Role |
|---|---|---|---|
| `iam-server` | 9083 | `iamdb`/`iam` | Users & admin users, Argon2id hashing, password reset, internal credential validation |
| `auth-server` | 9081 | `authdb`/`auth` | Spring Authorization Server: OAuth2/OIDC, JWTs, JDBC clients/authorizations/consents |
| `gateway` | 9080 | — | Spring Cloud Gateway: JWT validation + `X-Authenticated-*` header enrichment |
| `resource-server` | 9082 | `resourcedb`/`resource_app` | Sample protected API (scopes, roles, owner-based checks) |
| `web-client` | 9084 | — | Browser BFF (`spring oauth2Login`) |

Traffic: browser → gateway → services; auth-server talks to IAM for password
validation via `X-Internal-Token`; each service validates JWTs independently.

---

## 2. What was verified end-to-end (all working after PR #2)

- Project smoke test: **all 12 steps pass** (`./smoke-test.sh`, after
  `docker compose up -d postgres` and starting the four services).
- OIDC discovery, JWKS endpoint, client_credentials flow.
- Full browser authorization-code flow **with PKCE**:
  anonymous `/oauth2/authorize` → login page → login → resume → code →
  token exchange (access + refresh + id_token).
- Refresh-token flow (rotating refresh tokens) — refreshed tokens retain
  `sub`, `email`, `roles`, `user_type` claims.
- Token claims: `sub` = user UUID, `aud` = `resource-server`, `scope` is a
  JSON array (Security 7 shape), `roles` for admins.
- Gateway: public paths open, authenticated paths require Bearer token,
  header enrichment (`X-Authenticated-Subject/Client/Scopes/Roles/User-Type`),
  forged inbound headers stripped.
- Admin APIs (list/create users & admins, groups, password reset) with
  `ROLE_ADMIN` / `ROLE_ADMIN_GROUP_*` checks.
- Resource CRUD with `SCOPE_read`/`SCOPE_write`, owner-or-admin checks.
- Password-reset request (202), internal revocation endpoint (deletes stored
  authorizations; correct-token 200 / wrong-token 401), `/userinfo` endpoint.
- **Key-rotation experiment**: restarting auth-server changes the JWK `kid`;
  tokens issued before the restart fail inconsistently as each service's JWKS
  cache expires (gateway rejected while resource-server still accepted).
  → This is the top remaining production issue (see A.1).

Login for manual testing: `admin@localhost` / `admin123` (account type ADMIN),
seeded by IAM migrations.

---

## 3. Defects fixed in PR #2 (for context when revisiting)

1. Boot 4 no longer auto-configures the AS security filter chain → all
   `/oauth2/**` + `/.well-known/**` endpoints 302'd to the login page.
   Added `@Order(1)` chain with `http.oauth2AuthorizationServer { ... }`.
2. Schema mismatch: AS tables in schema `auth` but JDBC queries unqualified →
   fixed with Hikari `connection-init-sql: SET search_path TO auth, public`.
3. Seeded client secrets wrong + Security 7 requires `{bcrypt}` prefixes →
   migrations `V5__prefix_client_secret_hashes.sql`,
   `V6__fix_client_secret_hashes.sql`.
4. Gateway returned 401 on every authenticated route: Reactor bug —
   `getContext().flatMap { chain.filter(...) }.switchIfEmpty(...)` fired the
   fallback after the downstream `Mono<Void>` completed empty, clobbering the
   200. Fixed with `defaultIfEmpty(SecurityContextImpl())`.
5. Authorization-code grant 500 NPE: Security 7 reads the code TTL from the
   client's `token_settings` → `V7__web_client_authorization_code_ttl.sql`.
6. `principal_name varchar(200)` overflow: `IamPrincipal` wasn't a
   `java.security.Principal` → `Authentication.getName()` fell back to the
   data-class `toString()`. Now implements `Principal`, `getName() = userId`.
7. Jackson 3 `PolymorphicTypeValidator` denied the custom `IamPrincipal` type
   id when deserializing stored authorizations → `ProfileEnrichingAuthorizationService`
   persists a standard token (String principal) + a plain profile-claims map;
   token customizer reads both forms.
8. Unauthenticated `/oauth2/authorize` returned `invalid_request` instead of
   the login page → custom `errorResponseHandler` saves request + redirects.
9. IAM admin endpoints always 403: default JWT converter never maps `roles` →
   `JwtRolesGrantedAuthoritiesConverter`.
10. IAM controllers NPE'd: `@AuthenticationPrincipal JwtAuthenticationToken`
    resolves to null in Security 7 → switched to `Jwt`; non-UUID subjects 404.
11. `scope` claim is a JSON array in Security 7 → resource-server converter
    updated so `SCOPE_*` authorities resolve.
12. `AuthorizationChecker.canRead` let any user read any resource → now
    owner-or-admin.
13. `/internal/**` blocked by CSRF/form-login → permitted + CSRF-ignored
    (still guarded by `X-Internal-Token`).
14. CRLF line endings in `gradlew` and `smoke-test.sh` → normalized.

---

## 4. REMAINING WORK (the actual backlog)

### A. Production blockers — do these before any real deployment

1. **Persistent signing keys** *(highest priority)*
   `JwkConfig` (auth-server) and `PasswordResetService` (IAM) generate fresh
   keys every startup; `auth.signing.key-path` / `iam.signing-key-path` are
   dead config. Every restart invalidates all tokens and reset links.
   Fix: persist keys (file/Vault/KMS), add `kid`-based rotation.

2. **Hardcoded issuer/audience**
   `AuthorizationServerSettings` pins `http://localhost:9081`; downstream
   `issuer-uri`/`jwk-set-uri` default to localhost; token `aud` hardcoded to
   `resource-server`. Make env-driven.

3. **Dev secrets in code**
   Seeded admin `admin123`, client secrets, DB passwords, `dev-internal-token`
   defaults. Inject via env/secrets manager; forbid defaults in prod.

4. **No abuse controls**
   No rate limiting or brute-force protection on login/register/
   forgot-password; no failed-attempt tracking, no account lockout/unlock.

5. **Email is a stub**
   `email.enabled=false` logs reset links instead of sending; no SMTP, no
   verification emails; `emailVerified` field is unused.

6. **Instant revocation gap**
   Revoke endpoint deletes stored authorizations but issued JWTs stay valid
   until expiry. Needs short access-token TTLs + denylist or reference tokens.

7. **No audit logging**
   Admin actions and security events (logins, failures, resets) not recorded.

8. **Observability off**
   Only `/actuator/health`; no metrics/tracing; `org.springframework.security:
   DEBUG` still on in auth-server `application.yml`.

### B. Functional gaps

9. Consent screen missing (consent force-disabled for `web-client`); no OIDC
   back-channel logout wiring.
10. Session management UX: no "my sessions" page, no admin session kill;
    Spring Session JDBC cleanup job not configured.
11. Dynamic client registration/management (RFC 7591) — clients are DB seeds
    only.
12. Password policy depth: length-only; add history + breached-password check.
13. Fine-grained authorization beyond group roles (OPA/Cedar) if needed.

### C. Platform & ops

14. Containerization/CI-CD: compose only runs Postgres; 5 Dockerfiles not in
    a current compose/K8s setup; **no CI workflows at all**.
15. Tests are thin: only context-load tests + one password test; smoke test
    is not idempotent (fixed email `smoketest@example.com`). Highest-value
    investment: Testcontainers integration tests for the OAuth flows.
16. Network/ops hardening: TLS/HSTS, CORS policy, gateway rate limiting/
    retries, multi-replica HA.
17. Housekeeping: `spring-boot-flyway-4.0.6.jar` is a stray untracked file in
    the repo root (delete or gitignore); merged branch
    `fix/boot4-security7-production-readiness` can be deleted.

### D. Company road-map (good-to-haves, in order)

1. MFA: TOTP first, WebAuthn/passkeys after; step-up auth for admin endpoints.
2. Enterprise SSO: SAML/OIDC federation, JIT provisioning, SCIM sync.
3. Token hardening: reference tokens, introspection, DPoP for high-value APIs.
4. User-facing privacy: "my apps/grants" page to view/revoke consents.
5. Compliance: GDPR export/delete, consent records, forced rotation policies.

### E. Small leftovers from PR #2 to revisit

- `errorResponseHandler` fallback returns a plain 400 for non-browser OAuth
  errors instead of the standard OAuth error redirect (deliberate tradeoff).
- `web-client` BFF dashboard never browser-verified.
- Password-reset *completion* couldn't be fully tested without real email.
- IAM `/api/v1/auth/login` returns profile data without a token (debug-style
  endpoint) — keep off the public surface.

---

## 5. How to reproduce the verification environment

```bash
# 1. Postgres
docker compose up -d postgres

# 2. Services (separate terminals), IAM before auth-server:
./gradlew :iam-server:bootRun
./gradlew :auth-server:bootRun
./gradlew :resource-server:bootRun
./gradlew :gateway:bootRun
./gradlew :web-client:bootRun   # optional BFF

# 3. Verify
./smoke-test.sh

# Browser authorization-code flow:
# http://localhost:9081/oauth2/authorize?client_id=web-client&response_type=code&redirect_uri=http://localhost:9081/callback&scope=openid+profile+read+write
# (login admin@localhost / admin123, type ADMIN)

# Client credentials:
# curl -X POST http://localhost:9081/oauth2/token -u service-client:service-secret -d "grant_type=client_credentials&scope=read"
```

### Sandboxed-session notes (DSH environment quirks)

- `~/.gradle` and `~/.local/share/kotlin` were read-only in the sandbox;
  worked around with `GRADLE_USER_HOME=$PWD/.gradle-home` (already gitignored)
  and in-process Kotlin compilation
  (`-Dkotlin.compiler.execution.strategy=in-process`).
- Flyway checksum mismatches after schema resets: drop the app schema and let
  Flyway re-run cleanly, e.g. for IAM:
  `docker exec auth-platform-postgres-1 psql -U postgres -d iamdb -c "DROP SCHEMA iam CASCADE; CREATE SCHEMA iam AUTHORIZATION iam_user;"`
- Smoke test is NOT idempotent: delete `smoketest@example.com` from
  `iam.users` between runs.
- `gradlew` / `smoke-test.sh` had CRLF endings (fixed in PR #2); if a fresh
  clone still fails to execute, check line endings again.
