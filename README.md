# Auth Platform

A Kotlin/Spring Boot authentication platform with five services:

- **iam-server**: user identity, admin users, password management, and internal credential validation.
- **auth-server**: OAuth2/OIDC authorization server that issues JWTs and delegates password checks to IAM.
- **gateway**: Spring Cloud Gateway reverse proxy that validates JWTs and forwards requests.
- **resource-server**: sample protected API that demonstrates scopes, roles, and owner-based access checks.
- **web-client**: browser BFF that runs the authorization-code flow (`spring oauth2Login`).

The full stack (all five services + PostgreSQL) runs from Docker Compose; the services can also be started from Gradle for local development.

## Contents

- [Architecture](#architecture)
- [Services](#services)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Running Services](#running-services)
- [Databases](#databases)
- [Configuration](#configuration)
- [OAuth Clients and Seed Data](#oauth-clients-and-seed-data)
- [Common Requests](#common-requests)
- [Gateway Routes](#gateway-routes)
- [Tests](#tests)
- [Smoke Test](#smoke-test)
- [Project Layout](#project-layout)
- [Troubleshooting](#troubleshooting)

## Architecture

```text
Client
  |
  v
Gateway :9080
  |---------------------> Resource Server :9082
  |
  +---------------------> IAM Server :9083

Auth Server :9081 <---- internal credential validation ---- IAM Server :9083
      |
      +---- PostgreSQL authdb

IAM Server :9083
      |
      +---- PostgreSQL iamdb

Resource Server :9082
      |
      +---- PostgreSQL resourcedb
```

Traffic normally enters through the gateway. The auth server is contacted directly for OAuth2/OIDC flows. Downstream services validate JWTs independently; gateway-added `X-Authenticated-*` headers are convenience metadata, not the security authority.

## Services

| Service | Port | Database | Main role |
|---|---:|---|---|
| `iam-server` | `9083` | `iamdb`, schema `iam` | Users, admin users, password reset, internal credential validation |
| `auth-server` | `9081` | `authdb`, schema `auth` | OAuth2/OIDC authorization server, tokens, clients, sessions |
| `gateway` | `9080` | none | JWT-validating reverse proxy |
| `resource-server` | `9082` | `resourcedb`, schema `resource_app` | Sample protected API |
| `web-client` | `9084` | none | Browser BFF / OAuth2 client |

## Tech Stack

| Component | Version |
|---|---|
| Java | 21 |
| Kotlin | 2.3.21 |
| Spring Boot | 4.0.6 |
| Spring Cloud | 2025.1.1 |
| Spring Security | 7.0.x, managed by Boot |
| Spring Authorization Server | Boot OAuth2 Authorization Server starter |
| Spring Session JDBC | 4.0.3 |
| Flyway | Boot-managed, with PostgreSQL database support |
| PostgreSQL | 16 |
| Testcontainers | 2.0.5 in module test dependencies |
| Gradle | wrapper-provided Gradle |

## Quick Start

Prerequisites:

- JDK 21 (for Gradle runs; Docker-only runs need just Docker)
- Docker Desktop or Docker Engine with Compose
- `jq`, only if you want to run `smoke-test.sh`

**Option A — everything in Docker:**

```bash
docker compose up --build -d
./smoke-test.sh          # after all services report healthy
```

**Option B — Postgres in Docker, services from Gradle:**

```bash
docker compose up -d postgres
```

Run the services in separate terminals:

```bash
./gradlew :iam-server:bootRun
./gradlew :auth-server:bootRun
./gradlew :resource-server:bootRun
./gradlew :gateway:bootRun
./gradlew :web-client:bootRun
```

Useful checks:

```bash
docker compose ps
curl http://localhost:9083/actuator/health
curl http://localhost:9081/actuator/health
curl http://localhost:9082/actuator/health
curl http://localhost:9080/actuator/health
```

## Running Services

### Full stack via Docker Compose

`docker-compose.yml` defines Postgres plus all five application services with
healthchecks, startup ordering, and named volumes. Signing keys are generated
on first boot into the `iam-secrets` / `auth-secrets` volumes and survive
restarts, so issued tokens stay valid.

```bash
docker compose up --build -d     # build + start everything
docker compose ps                # watch healthchecks converge
docker compose logs -f gateway   # per-service logs
docker compose down              # stop (volumes preserved)
docker compose down -v           # stop and wipe databases AND signing keys
```

Only Postgres:

```bash
docker compose up -d postgres
docker compose logs -f postgres
docker compose down
```

To reset all local databases (keeps the services running from Gradle):

```bash
docker compose down -v
docker compose up -d postgres
```

The first Postgres startup runs [docker/postgres/init/01-create-databases.sql](docker/postgres/init/01-create-databases.sql), which creates:

- `auth_user` / `authdb`
- `iam_user` / `iamdb`
- `resource_user` / `resourcedb`

### Local Service Order

Start IAM before auth if you plan to use the login flow, because auth delegates password validation to IAM. Resource server and gateway can start after auth.

Recommended order:

1. `docker compose up -d postgres`
2. `./gradlew :iam-server:bootRun`
3. `./gradlew :auth-server:bootRun`
4. `./gradlew :resource-server:bootRun`
5. `./gradlew :gateway:bootRun`
6. `./gradlew :web-client:bootRun`

## Databases

Each database has one application-owned schema and independent Flyway migrations.

| Service | JDBC URL | User | Password | Schema |
|---|---|---|---|---|
| auth-server | `jdbc:postgresql://localhost:5432/authdb` | `auth_user` | `auth_pass` | `auth` |
| iam-server | `jdbc:postgresql://localhost:5432/iamdb` | `iam_user` | `iam_pass` | `iam` |
| resource-server | `jdbc:postgresql://localhost:5432/resourcedb` | `resource_user` | `resource_pass` | `resource_app` |

Flyway creates schemas and tables on service startup. Hibernate runs with `ddl-auto: validate`, so startup fails if migrations and entities do not match.

Migration locations:

```text
auth-server/src/main/resources/db/migration/
iam-server/src/main/resources/db/migration/
resource-server/src/main/resources/db/migration/
```

## Configuration

All services are configured through environment variables with development
defaults baked into `application.yml`. Copy [.env.example](.env.example) to
`.env` and adjust it for your deployment (`docker compose` picks up `.env`
automatically).

### Auth Server

Important settings in [auth-server/src/main/resources/application.yml](auth-server/src/main/resources/application.yml):

| Env var | Default | Purpose |
|---|---|---|
| `AUTH_DB_USER` / `AUTH_DB_PASS` | `auth_user` / `auth_pass` | Postgres credentials |
| `IAM_BASE_URL` | `http://localhost:9083` | IAM internal validation URL |
| `IAM_INTERNAL_TOKEN` | `dev-internal-token` | Shared internal-service secret (must match IAM) |
| `AUTH_ISSUER` | `http://localhost:9081` | `iss` claim + discovery document |
| `AUTH_SIGNING_KEY_PATH` | empty | Persisted JWKSet file; empty = ephemeral (dev only) |
| `AUTH_TOKEN_AUDIENCE` | `resource-server` | Token `aud` (comma-separated list allowed) |
| `AUTH_ACCESS_TOKEN_TTL` | `15m` | Access-token lifetime (applied to every client) |
| `AUTH_REFRESH_TOKEN_TTL` | `12h` | Refresh-token lifetime (applied to every client) |
| `AUTH_HSTS_ENABLED` | `false` | Enable HSTS (only behind TLS!) |
| `AUTH_CLIENT_REGISTRATION_TOKEN` | empty | Enables `POST /api/v1/clients` when set |

### IAM Server

Important settings in [iam-server/src/main/resources/application.yml](iam-server/src/main/resources/application.yml):

| Env var | Default | Purpose |
|---|---|---|
| `IAM_DB_USER` / `IAM_DB_PASS` | `iam_user` / `iam_pass` | Postgres credentials |
| `IAM_INTERNAL_TOKEN` | `dev-internal-token` | Shared internal-service secret (must match auth-server/gateway) |
| `IAM_SIGNING_KEY_PATH` | empty | Persisted HMAC key file; empty = ephemeral (dev only) |
| `IAM_SIGNING_PREVIOUS_KEY_PATHS` | empty | Optional rotation keys still accepted for verification |
| `IAM_LOGIN_MAX_ATTEMPTS` | `5` | Failed attempts before lockout |
| `IAM_LOGIN_LOCKOUT_MINUTES` | `15` | Lockout duration |
| `IAM_PASSWORD_HISTORY_SIZE` | `5` | Recent passwords that cannot be reused |
| `IAM_PASSWORD_COMMON_CHECK` | `true` | Reject a curated list of common passwords |
| `IAM_AUTH_SERVER_URL` | `http://localhost:9081` | auth-server base URL (token revocation on account deletion) |
| `IAM_AUDIT_RETENTION_DAYS` | `90` | Audit-log retention (0 disables pruning) |
| `EMAIL_ENABLED` / `EMAIL_FROM` | `false` / `no-reply@localhost` | Email delivery (logs links when disabled) |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` | — | SMTP server for real email |
| `EMAIL_RESET_LINK_BASE` / `EMAIL_VERIFICATION_LINK_BASE` | `http://localhost:3000/...` | Link bases embedded in emails |
| `EMAIL_VERIFICATION_REQUIRED` | `false` | Block login until the email is verified |

### Resource Server

Important settings in [resource-server/src/main/resources/application.yml](resource-server/src/main/resources/application.yml):

| Env var | Default |
|---|---|
| `RESOURCE_DB_USER` / `RESOURCE_DB_PASS` | `resource_user` / `resource_pass` |
| `AUTH_ISSUER` | `http://localhost:9081` |
| `AUTH_JWKS_URI` | `http://localhost:9081/oauth2/jwks` |

### Gateway

Important settings in [gateway/src/main/resources/application.yml](gateway/src/main/resources/application.yml):

| Env var | Default | Purpose |
|---|---|---|
| `AUTH_ISSUER` / `AUTH_JWKS_URI` | `http://localhost:9081` / `.../oauth2/jwks` | JWT validation |
| `GATEWAY_HSTS_ENABLED` | `false` | HSTS (only behind TLS!) |
| `GATEWAY_CORS_ALLOWED_ORIGINS` | empty | Comma-separated allowed origins; empty = CORS disabled |
| `GATEWAY_RATE_LIMIT_ENABLED` / `GATEWAY_RATE_LIMIT_PER_MINUTE` | `true` / `30` | Per-IP limit on register/forgot-password |
| `GATEWAY_REVOCATION_CHECK_ENABLED` | `false` (Compose: `true`) | Check presented JWTs against the auth-server denylist |
| `AUTH_SERVER_URL` | `http://localhost:9081` | Denylist-check target |

Public gateway paths are configured under `gateway.public-paths`.

## OAuth Clients and Seed Data

OAuth clients are seeded by auth-server Flyway migration `V2__seed_oauth_clients.sql`.

Common development client:

| Client | Secret | Grant | Scope |
|---|---|---|---|
| `service-client` | `service-secret` | `client_credentials` | `read` |

IAM seed data includes default admin groups and a default admin account in the IAM migrations. See:

- [V3__seed_admin_groups.sql](iam-server/src/main/resources/db/migration/V3__seed_admin_groups.sql)
- [V4__seed_default_admin.sql](iam-server/src/main/resources/db/migration/V4__seed_default_admin.sql)

Default local admin:

| Field | Value |
|---|---|
| Email | `admin@localhost` |
| Username | `admin` |
| Password | `admin123` |
| Group | `FULL_ACCESS` |
| Login account type | `Admin` |

The login form accepts either the email or username.

## Common Requests

### Register a User

```bash
curl -s -X POST http://localhost:9083/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"securepass123","firstName":"Alice","lastName":"Johnson"}'
```

### Validate Credentials (internal, the real login path)

There is deliberately **no public login endpoint**. Credential checks happen
only over the internal, `X-Internal-Token`-protected endpoint that auth-server
uses:

```bash
curl -s -X POST http://localhost:9083/internal/auth/validate \
  -H "Content-Type: application/json" \
  -H "X-Internal-Token: dev-internal-token" \
  -d '{"email":"alice@example.com","password":"securepass123","userType":"USER"}'
```

Failed attempts are audited and count toward the account lockout (5 failures →
15 minutes, HTTP 429 with `Retry-After`).

### Get a Client Credentials Token

```bash
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:9081/oauth2/token \
  -u "service-client:service-secret" \
  -d "grant_type=client_credentials&scope=read")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)
```

### Call Through the Gateway

```bash
curl -s http://localhost:9080/api/v1/public/status

curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:9080/api/v1/whoami

curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:9080/api/v1/status

curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:9080/iam/v1/status
```

### Browser Authorization Code Flow

For the browser BFF flow, start `web-client` and open:

```text
http://localhost:9084/
```

The web client sends you through auth-server login, stores a browser session, and calls JWT-protected gateway endpoints server-side with the OAuth access token.

For a raw authorization URL, open:

```text
http://localhost:9081/oauth2/authorize?client_id=web-client&response_type=code&redirect_uri=http://localhost:9084/login/oauth2/code/auth-platform&scope=openid+profile+read+write
```

Then log in with email, password, and account type. Clients with
`require_authorization_consent` (including `web-client`) show a consent page
(`/oauth2/consent`) before the code is issued; the choice is remembered per
user + client.

If you open the auth-server login page directly at `http://localhost:9081/login`, a successful login redirects to `http://localhost:9081/login/success` by default. Override that with `AUTH_LOGIN_SUCCESS_URL` if you want a different local success target.

### Register a Client Dynamically

Disabled unless a registration token is configured. Start auth-server with
`AUTH_CLIENT_REGISTRATION_TOKEN=<strong-random-value>`, then:

```bash
curl -s -X POST http://localhost:9081/internal/clients \
  -H "Authorization: Bearer <strong-random-value>" \
  -H "Content-Type: application/json" \
  -d '{
        "clientName": "My App",
        "redirectUris": ["http://localhost:3000/callback"],
        "grantTypes": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile", "read"]
      }'
```

The response contains the generated `client_id`/`client_secret` (the secret is
shown once, bcrypt-hashed at rest). The endpoint is internal (like the other
`/internal/**` services), so it is not exposed through the gateway.

## Gateway Routes

| Gateway path | Target |
|---|---|
| `/api/v1/**` | resource-server `http://localhost:9082` |
| `/iam/v1/**` | iam-server `http://localhost:9083/api/v1/**` |

Public paths include health checks, IAM auth endpoints, and resource public endpoints.

The gateway removes forged inbound identity headers and adds:

- `X-Authenticated-Subject`
- `X-Authenticated-Client`
- `X-Authenticated-Scopes`
- `X-Authenticated-Roles`
- `X-Authenticated-User-Type`

## Tests

Run all tests:

```bash
./gradlew clean check --no-daemon
```

Run one module:

```bash
./gradlew :auth-server:test --no-daemon
./gradlew :iam-server:test --no-daemon
./gradlew :resource-server:test --no-daemon
./gradlew :gateway:test --no-daemon
```

The DB-backed module tests use Testcontainers and require Docker access.

On WSL, if `docker info` works in a fresh WSL terminal but not in an older terminal/session, restart the terminal or run the Gradle command from a fresh shell. Docker group membership is captured when the shell starts.

## Smoke Test

`smoke-test.sh` expects all four services to already be running locally. It is
idempotent: it uses a randomized email and cleans up its rows (and leftovers
from interrupted runs) on exit, so it can be re-run freely.

```bash
docker compose up -d postgres
./gradlew :iam-server:bootRun
./gradlew :auth-server:bootRun
./gradlew :resource-server:bootRun
./gradlew :gateway:bootRun

./smoke-test.sh
```

Run each `bootRun` command in its own terminal. The same script runs in CI
against the Compose-managed Postgres.

`smoke-bff.sh` additionally exercises the full browser flow through the
web-client BFF (`:9084`): oauth2Login redirect → login → consent → callback →
dashboard. It needs `web-client` running and the `webdb` database.

### Self-service data export and erasure

With a user access token:

```bash
# GDPR art. 20 — export your data
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:9083/api/v1/me/export

# GDPR art. 17 — delete your account (anonymizes + revokes tokens)
curl -s -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:9083/api/v1/me
```

## Project Layout

```text
.
├── auth-server/
├── gateway/
├── iam-server/
├── resource-server/
├── docker/
│   └── postgres/init/01-create-databases.sql
├── docker-compose.yml
├── gradle/
├── gradlew
├── gradlew.bat
└── smoke-test.sh
```

## Production Readiness Checklist

Before deploying:

1. **Secrets** — set strong values for `IAM_INTERNAL_TOKEN`, `*_DB_PASS`,
   `WEB_CLIENT_SECRET`, and (if used) `AUTH_CLIENT_REGISTRATION_TOKEN`. With
   `SPRING_PROFILES_ACTIVE=prod`, each server refuses to start if a known dev
   default secret or a missing signing-key path is detected — including an
   enabled admin account still using `admin123`.
2. **Signing keys** — point `AUTH_SIGNING_KEY_PATH` and `IAM_SIGNING_KEY_PATH`
   at persistent, permission-restricted (0600) files outside the container
   ephemeral layer. Generated automatically on first boot if missing.
3. **Issuer/audience** — set `AUTH_ISSUER` to the externally reachable URL
   (must match what downstream services validate) and `AUTH_TOKEN_AUDIENCE`
   to your resource-server audience(s).
4. **Revocation** — keep `GATEWAY_REVOCATION_CHECK_ENABLED=true` (the Compose
   default) so revoked tokens are rejected immediately, not just at expiry.
5. **Email** — `EMAIL_ENABLED=true` + `SMTP_*` for real password-reset and
   verification emails; consider `EMAIL_VERIFICATION_REQUIRED=true`.
6. **TLS** — terminate TLS at a proxy in front of the gateway; only then
   enable `GATEWAY_HSTS_ENABLED` / `AUTH_HSTS_ENABLED`. Don't publish the
   backend service ports (9081–9084) publicly; expose only the gateway.
7. **Observability** — scrape `/actuator/prometheus` per service; non-health
   actuator endpoints require admin authentication. All services ship with the
   OpenTelemetry bridge — set `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces.
8. **GDPR basics** — self-service `GET /api/v1/me/export` (art. 20) and
   `DELETE /api/v1/me` (art. 17: anonymizes the account and revokes all
   outstanding tokens via the auth-server) are available behind a user token.
8. **CI** — the GitHub Actions workflow (build+tests, e2e smoke, Docker
   builds) runs on every push to `main`; consider branch protection.

Known remaining gaps are tracked in
[docs/production-readiness-research.md](docs/production-readiness-research.md)
§4/§6 (consent is implemented; dynamic client registration is token-gated;
MFA/SSO/reference tokens are roadmap items).

## Troubleshooting

### `Connection to localhost:5432 refused`

PostgreSQL is not running or port `5432` is not published.

```bash
docker compose up -d postgres
docker compose ps
```

### `password authentication failed`

Check that the app is using the credentials from this README. If you changed `AUTH_DB_USER`, `AUTH_DB_PASS`, or the Compose volume already exists with old users/passwords, reset the local volume:

```bash
docker compose down -v
docker compose up -d postgres
```

### `Schema validation: missing table`

Flyway either did not run or Hibernate is looking at the wrong schema. The current configs set:

- IAM: Flyway schema `iam`, Hibernate default schema `iam`
- Resource server: Flyway schema `resource_app`, Hibernate default schema `resource_app`
- Auth server: Flyway schema `auth`

Resetting the local database volume is often the fastest way to clear stale schema state during development.

### Native WSL Docker socket permission denied

Check:

```bash
id
ls -l /var/run/docker.sock
docker info
```

Your user should be in the `docker` group and the socket should be owned by `root docker` or otherwise group-accessible. If group membership was just changed, open a new WSL terminal.
