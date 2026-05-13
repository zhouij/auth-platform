# Auth Platform

A Kotlin/Spring Boot authentication platform with four services:

- **iam-server**: user identity, admin users, password management, and internal credential validation.
- **auth-server**: OAuth2/OIDC authorization server that issues JWTs and delegates password checks to IAM.
- **gateway**: Spring Cloud Gateway reverse proxy that validates JWTs and forwards requests.
- **resource-server**: sample protected API that demonstrates scopes, roles, and owner-based access checks.

The repository is intended for local development with the services running from Gradle and PostgreSQL running from Docker Compose.

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

- JDK 21
- Docker Desktop or Docker Engine with Compose
- `jq`, only if you want to run `smoke-test.sh`

Start the shared database:

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

### PostgreSQL

`docker-compose.yml` intentionally contains only infrastructure needed by local services. It does **not** run the application services.

```bash
docker compose up -d postgres
docker compose logs -f postgres
docker compose down
```

To reset all local databases:

```bash
docker compose down -v
docker compose up -d postgres
```

The first container startup runs [docker/postgres/init/01-create-databases.sql](docker/postgres/init/01-create-databases.sql), which creates:

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

### Auth Server

Important defaults in [auth-server/src/main/resources/application.yml](auth-server/src/main/resources/application.yml):

| Property | Default |
|---|---|
| `spring.datasource.url` | `jdbc:postgresql://localhost:5432/authdb` |
| `spring.datasource.username` | `${AUTH_DB_USER:auth_user}` |
| `spring.datasource.password` | `${AUTH_DB_PASS:auth_pass}` |
| `iam.base-url` | `${IAM_BASE_URL:http://localhost:9083}` |
| `iam.internal-token` | `${IAM_INTERNAL_TOKEN:dev-internal-token}` |
| `auth.signing.key-path` | `${AUTH_SIGNING_KEY_PATH:}` |

If `auth.signing.key-path` is empty, the app uses its local key configuration. For deployment, provide a persistent signing key.

### IAM Server

Important defaults in [iam-server/src/main/resources/application.yml](iam-server/src/main/resources/application.yml):

| Property | Default |
|---|---|
| `spring.datasource.url` | `jdbc:postgresql://localhost:5432/iamdb` |
| `spring.datasource.username` | `iam_user` |
| `spring.datasource.password` | `iam_pass` |
| `iam.internal-token` | `dev-internal-token` |
| `email.enabled` | `false` |

### Resource Server

Important defaults in [resource-server/src/main/resources/application.yml](resource-server/src/main/resources/application.yml):

| Property | Default |
|---|---|
| `spring.datasource.url` | `jdbc:postgresql://localhost:5432/resourcedb` |
| `spring.datasource.username` | `resource_user` |
| `spring.datasource.password` | `resource_pass` |
| `spring.security.oauth2.resourceserver.jwt.issuer-uri` | `http://localhost:9081` |
| `spring.security.oauth2.resourceserver.jwt.jwk-set-uri` | `http://localhost:9081/oauth2/jwks` |

### Gateway

Important defaults in [gateway/src/main/resources/application.yml](gateway/src/main/resources/application.yml):

| Property | Default |
|---|---|
| `server.port` | `9080` |
| `AUTH_ISSUER` | `http://localhost:9081` |
| `AUTH_JWKS_URI` | `http://localhost:9081/oauth2/jwks` |

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

### Check IAM Login

```bash
curl -s -X POST http://localhost:9083/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"securepass123"}'
```

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

Then log in with email, password, and account type.

If you open the auth-server login page directly at `http://localhost:9081/login`, a successful login redirects to `http://localhost:9081/login/success` by default. Override that with `AUTH_LOGIN_SUCCESS_URL` if you want a different local success target.

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

`smoke-test.sh` expects all four services to already be running locally.

```bash
docker compose up -d postgres
./gradlew :iam-server:bootRun
./gradlew :auth-server:bootRun
./gradlew :resource-server:bootRun
./gradlew :gateway:bootRun

./smoke-test.sh
```

Run each `bootRun` command in its own terminal.

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
