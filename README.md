# Auth Gateway System

A four-service authentication and API gateway monorepo built with **Kotlin**, **Spring Boot 3.5**, and **PostgreSQL**. It demonstrates a production-grade OAuth2 + IAM architecture: user identity management, OAuth2/OIDC token issuance, a JWT-validating reverse proxy, and a domain service with fine-grained role-, scope-, and ownership-based access control.

## Table of Contents

- [Architecture](#architecture)
- [Service Overview](#service-overview)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Run with Docker Compose](#run-with-docker-compose)
  - [Run Locally for Development](#run-locally-for-development)
- [End-to-End Flow](#end-to-end-flow)
- [API Reference](#api-reference)
  - [IAM Server `:9083`](#iam-server-9083)
  - [Auth Server `:9081`](#auth-server-9081)
  - [Gateway `:9080`](#gateway-9080)
  - [Resource Server `:9082`](#resource-server-9082)
- [Database Design](#database-design)
  - [Databases and Schemas](#databases-and-schemas)
  - [Entity-Relationship Overview](#entity-relationship-overview)
  - [Flyway Migrations](#flyway-migrations)
- [Security Design](#security-design)
  - [Password Hashing](#password-hashing)
  - [JWT Token Claims](#jwt-token-claims)
  - [Audience Enforcement](#audience-enforcement)
  - [Refresh Token Rotation & Revocation](#refresh-token-rotation--revocation)
  - [IAM Internal API Protection](#iam-internal-api-protection)
  - [Header Sanitation in Gateway](#header-sanitation-in-gateway)
  - [CORS Policy](#cors-policy)
  - [Threat Mitigations](#threat-mitigations)
- [Authorization Patterns](#authorization-patterns)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [OAuth2 Registered Clients](#oauth2-registered-clients)
  - [Seeded Users](#seeded-users)
- [Project Layout](#project-layout)
- [Development Guide](#development-guide)
  - [Building](#building)
  - [Running Tests](#running-tests)
  - [Adding a Flyway Migration](#adding-a-flyway-migration)
  - [Adding a New Domain Service](#adding-a-new-domain-service)
- [Deployment](#deployment)
  - [Docker Images](#docker-images)
  - [Docker Compose](#docker-compose)
  - [Production Considerations](#production-considerations)
- [Observability](#observability)
- [Extending the System](#extending-the-system)
- [License](#license)

---

## Architecture

```text
                          +---------------------+
                          |     IAM Server      | :9083
                          |---------------------|
                          | POST /api/v1/auth/  |
                          |       register       |
                          | POST /api/v1/auth/  |
                          |       login          |
                          | POST /api/v1/auth/  |
                          |   forgot-password    |
                          | POST /api/v1/auth/  |
                          |   reset-password     |
                          | POST /internal/auth/|
                          |       validate      |
                          | GET  /api/v1/admin/ |
                          |       users         |
                          | GET  /api/v1/me     |
                          | PUT  /api/v1/me     |
                          | PUT  /api/v1/me/    |
                          |       password      |
                          +---------+-----------+
                                    ^
                                    | internal credential validation
                                    | (email + password + userType)
                                    |
                          +---------+-----------+
                          |    Auth Server      | :9081
                          |---------------------|
                          | /oauth2/authorize   |
                          | /oauth2/token       |
                          | /oauth2/jwks        |
                          | /oauth2/revoke      |
                          | /.well-known/       |
                          |   openid-config     |
                          | /login              |
                          +---------+-----------+
                                    |
                                    | JWT bearer tokens
                                    | (sub, email, user_type, roles, aud)
                                    v
                          +---------+-----------+
                          |       Gateway       | :9080
                          |---------------------|
                          | JWT validation      |
                          | header sanitation    |
                          | path routing        |
                          +----+----------+-----+
                               |           |
             /api/v1/** -------+           +------- /iam/v1/**
                               |                       |
                               v                       v
                     +---------+--------+   +----------+--------+
                     | Resource Server  |   |   IAM Server     |
                     | :9082            |   |   (proxy)        |
                     +------------------+   +-------------------+
```

**Trust boundaries:**

| Boundary | Between | Protection |
|----------|---------|------------|
| T1 | Client ↔ Gateway | TLS, JWT validation, rate limiting, CORS |
| T2 | Gateway ↔ Resource/IAM | Internal network; resource servers independently validate JWTs |
| T3 | Gateway ↔ Auth (JWKS) | Internal network; signature-based trust, no shared secrets |
| T4 | Auth ↔ IAM | Internal network; `X-Internal-Token` (→ mTLS in production); circuit breaker |
| T5 | All services ↔ PostgreSQL | Network isolation; per-service credentials; TLS in production |

## Service Overview

| Service | Port | Stack | Database | Purpose |
|---------|-----:|:------|:---------|:--------|
| **iam-server** | 9083 | Spring MVC + JPA | `iamdb` | User lifecycle: registration, login, credential validation, password reset, admin user/group management |
| **auth-server** | 9081 | Spring MVC + JDBC | `authdb` | OAuth2/OIDC Authorization Server: token issuance, consent, client registry, signing keys, token revocation |
| **gateway** | 9080 | Spring Cloud Gateway (WebFlux) | _None_ (stateless) | Reverse proxy: JWT validation, header enrichment, path-based routing |
| **resource-server** | 9082 | Spring MVC + JPA | `resourcedb` | Reference domain service demonstrating RBAC, scope checks, and owner-based access control |

### Service Responsibilities

**IAM Server** is the system of record for user identity. It manages two separate account types in two database tables:
- **Regular users** (`users` table): self-registration, Argon2id hashed passwords (64 MiB), no authorities
- **Admin users** (`admin_users` table): created by existing admins, stronger Argon2id (128 MiB), group-based authorities (`ROLE_ADMIN_GROUP_*`)

**Auth Server** issues OAuth2 access tokens, refresh tokens, and ID tokens. It delegates credential validation to the IAM server's internal API and never stores user passwords. It persists client registrations, authorizations, and consent decisions in PostgreSQL.

**Gateway** validates JWT signatures, issuer, expiry, and audience before forwarding requests. It strips potentially forged identity headers from inbound requests and sets `X-Authenticated-*` convenience headers for downstream services. Downstream services must still validate JWTs independently — these headers are hints, not the security authority.

**Resource Server** is a reference implementation showing how to build a domain service that:
- Validates JWTs independently (signature, issuer, expiry, audience)
- Extracts `SCOPE_*` and `ROLE_*` authorities from JWT claims
- Enforces method-level authorization with `@PreAuthorize`
- Performs owner-based resource access checks

## Tech Stack

| Component | Version | Notes |
|-----------|---------|-------|
| Kotlin | 2.1.21 | |
| Spring Boot | 3.5.14 | |
| Spring Cloud | 2025.1.1 | Gateway 5.0.1 |
| Spring Authorization Server | 1.5.7 | OAuth2 + OIDC |
| Spring Security | 6.5.x (managed by Boot) | |
| Spring Session | 3.5.0 | JDBC-backed sessions for auth server |
| Gradle | 8.14.2 | Kotlin DSL |
| PostgreSQL | 16 | One database per service |
| Flyway | 11.10.0 | Per-module schema migrations |
| Testcontainers | 1.21.3 | Integration tests |
| Java | 21 | Via `jvmToolchain(21)` |

## Quick Start

### Prerequisites

- JDK 21 or later
- Docker and Docker Compose (for containerised deployment)
- [jq](https://jqlang.github.io/jq/) (for the smoke test script)
- 4 GB RAM available for Docker

### Run with Docker Compose

This is the recommended way to run the full system. It starts PostgreSQL, runs Flyway migrations, then starts all four services in dependency order.

```bash
# Clone and enter the project
cd auth-platform

# Build and start all services
docker compose up --build -d

# Watch the logs (all services)
docker compose logs -f

# Wait for all services to become healthy
docker compose ps | grep healthy

# Run the smoke test
./smoke-test.sh
```

The startup order is:
1. `postgres` → `iam-server`
2. `iam-server` healthy → `auth-server`
3. `auth-server` healthy → `resource-server` and `gateway`

All services become healthy in approximately 60–90 seconds on first start (cold Gradle builds).

To tear down:

```bash
docker compose down -v
```

### Run Locally for Development

Start PostgreSQL first (via Docker or a local install), then run each service in a separate terminal:

```bash
# Terminal 1 — Start only PostgreSQL via Compose
docker compose up -d postgres

# Terminal 2 — IAM Server
cd iam-server && ../gradlew bootRun

# Terminal 3 — Auth Server
cd auth-server && ../gradlew bootRun

# Terminal 4 — Gateway
cd gateway && ../gradlew bootRun

# Terminal 5 — Resource Server
cd resource-server && ../gradlew bootRun
```

Each service auto-creates its database schema on first start via Flyway.

---

## End-to-End Flow

Here's a complete walkthrough of the happy path:

### 1. Register a User

```bash
curl -s -X POST http://localhost:9083/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"securepass123","firstName":"Alice","lastName":"Johnson"}'
```

Response: `201 Created` with the user's UUID.

### 2. Verify Login

```bash
curl -s -X POST http://localhost:9083/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"securepass123"}'
```

Response: `200 OK` with `userId`, `email`, `userType: "USER"`, and empty `authorities`.

### 3. Get an OAuth2 Access Token

Use the pre-seeded `service-client` (client credentials grant):

```bash
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:9081/oauth2/token \
  -u "service-client:service-secret" \
  -d "grant_type=client_credentials&scope=read")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)
echo "Token: $ACCESS_TOKEN"
```

Response includes `access_token`, `token_type: "Bearer"`, `expires_in`, and `scope`.

### 4. Access the Resource Server via the Gateway

```bash
# Public endpoint (no auth required)
curl -s http://localhost:9080/api/v1/public/status

# Authenticated endpoint (JWT required)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:9080/api/v1/whoami

# List resources (requires SCOPE_read)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:9080/api/v1/resources

# Admin endpoint (requires ROLE_ADMIN — 403 for service-client)
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:9080/api/v1/admin/resources
```

### 5. Authorization Code Flow (Browser)

For browser-based login with the `web-client`:

1. Open: `http://localhost:9081/oauth2/authorize?client_id=web-client&response_type=code&redirect_uri=http://localhost:3000/callback&scope=openid+read+write`
2. Log in with email, password, and account type (User / Admin)
3. Approve consent
4. Your callback receives an authorization code
5. Exchange the code for tokens at `POST /oauth2/token`

---

## API Reference

### IAM Server `:9083`

#### Public Endpoints (no auth required)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/auth/register` | Register a new user account |
| `POST` | `/api/v1/auth/login` | Diagnostic login check (returns user info without issuing tokens) |
| `POST` | `/api/v1/auth/forgot-password` | Request a password reset email. Requires `userType` in body. Always returns `202` |
| `POST` | `/api/v1/auth/reset-password` | Complete password reset using the JWT from the email link |

**Register request:**
```json
{
  "email": "alice@example.com",
  "password": "securepass123",
  "firstName": "Alice",
  "lastName": "Johnson"
}
```

**Login request:**
```json
{
  "email": "alice@example.com",
  "password": "securepass123"
}
```

**Forgot-password request:**
```json
{
  "email": "alice@example.com",
  "userType": "USER"
}
```

**Reset-password request:**
```json
{
  "token": "<reset-jwt-from-email>",
  "newPassword": "new-secure-password"
}
```

#### Self-Service Endpoints (JWT required, any user type)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/me` | Get the current user's own profile |
| `PUT` | `/api/v1/me` | Update own profile (firstName, lastName, username) |
| `PUT` | `/api/v1/me/password` | Change own password (requires current password) |

**Change password request:**
```json
{
  "currentPassword": "old-password",
  "newPassword": "new-password"
}
```

#### Admin User Management (`/api/v1/admin/users`) — requires `ROLE_ADMIN_GROUP_USER_MANAGEMENT` or `ROLE_ADMIN_GROUP_FULL_ACCESS`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/users` | List all regular users |
| `GET` | `/api/v1/admin/users/{email}` | Get a user by email |
| `PUT` | `/api/v1/admin/users/{email}` | Update user profile (firstName, lastName, username) |
| `PUT` | `/api/v1/admin/users/{email}/password` | Reset user password (admin override, no old password needed) |
| `POST` | `/api/v1/admin/users/{email}/disable` | Disable a user account |
| `POST` | `/api/v1/admin/users/{email}/enable` | Re-enable a user account |

#### Admin Admin Management (`/api/v1/admin/admins`) — requires `ROLE_ADMIN_GROUP_ADMIN_MANAGEMENT` or `ROLE_ADMIN_GROUP_FULL_ACCESS`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/admins` | List all admin users |
| `GET` | `/api/v1/admin/admins/{email}` | Get an admin by email |
| `POST` | `/api/v1/admin/admins` | Create a new admin account with group assignments |
| `PUT` | `/api/v1/admin/admins/{email}` | Update admin details and group memberships |
| `PUT` | `/api/v1/admin/admins/{email}/password` | Reset admin password |
| `POST` | `/api/v1/admin/admins/{email}/disable` | Disable an admin account |
| `POST` | `/api/v1/admin/admins/{email}/enable` | Re-enable an admin account |

**Create admin request:**
```json
{
  "email": "admin_alice@example.com",
  "password": "very-strong-admin-password-at-least-14-chars",
  "firstName": "Alice",
  "lastName": "Johnson",
  "groupNames": ["USER_MANAGEMENT"]
}
```

#### Admin Groups (`/api/v1/admin/groups`) — requires `ROLE_ADMIN`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/groups` | List available admin groups |

#### Internal API (protected by `X-Internal-Token`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/internal/auth/validate` | Validate credentials for a specific user type. Body: `{"email","password","userType"}`. Returns principal with authorities |
| `GET` | `/internal/users/{email}` | Load a user from `users` table by email |
| `GET` | `/internal/admin-users/{email}` | Load an admin from `admin_users` table by email |

### Auth Server `:9081`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/.well-known/openid-configuration` | None | OIDC discovery document |
| `GET` | `/oauth2/jwks` | None | JWT public keys (JWK Set) |
| `POST` | `/oauth2/token` | Client (Basic) | Token endpoint: `authorization_code`, `refresh_token`, `client_credentials` |
| `POST` | `/oauth2/revoke` | Client (Basic) | Revoke a refresh token |
| `GET` | `/oauth2/authorize` | Session | Authorization code consent/login flow |
| `GET` | `/login` | None | Custom login page (email + password + user type selector) |
| `POST` | `/login` | None | Process login form submission |
| `POST` | `/internal/auth/revoke-user/{userId}` | `X-Internal-Token` | Revoke all tokens for a user (called by IAM) |

**Login page:** The auth server serves a custom Thymeleaf login form at `/login` with three fields:
- **Email** — account email address
- **Password** — account password
- **Account Type** — dropdown: `User` or `Admin`

### Gateway `:9080`

All external traffic flows through the gateway. Routes are:

| Gateway Path | Upstream Service | Upstream Path | Auth Required |
|-------------|-----------------|---------------|---------------|
| `/api/v1/public/**` | resource-server `:9082` | `/api/v1/public/**` | No |
| `/api/v1/**` | resource-server `:9082` | `/api/v1/**` | Yes |
| `/iam/v1/auth/register` | iam-server `:9083` | `/api/v1/auth/register` | No |
| `/iam/v1/auth/login` | iam-server `:9083` | `/api/v1/auth/login` | No |
| `/iam/v1/auth/forgot-password` | iam-server `:9083` | `/api/v1/auth/forgot-password` | No |
| `/iam/v1/auth/reset-password` | iam-server `:9083` | `/api/v1/auth/reset-password` | No |
| `/iam/v1/**` | iam-server `:9083` | `/api/v1/**` | Yes |

The gateway enriches proxied requests with these headers (after stripping any inbound values):

| Header | Source |
|--------|--------|
| `X-Authenticated-Subject` | JWT `sub` |
| `X-Authenticated-Client` | JWT `client_id` |
| `X-Authenticated-Scopes` | JWT `scope` |
| `X-Authenticated-Roles` | JWT `roles` |
| `X-Authenticated-User-Type` | JWT `user_type` |

### Resource Server `:9082`

All resource server endpoints are accessed through the gateway at `/api/v1/...`.

| Method | Path | Auth Required | Description |
|--------|------|---------------|-------------|
| `GET` | `/api/v1/public/status` | No | Public health check |
| `GET` | `/api/v1/me` | Yes (any type) | Current user's JWT claims |
| `GET` | `/api/v1/whoami` | Yes (any type) | Full JWT claims inspection |
| `GET` | `/api/v1/resources` | `SCOPE_read` (ADMIN only) | List all resources |
| `GET` | `/api/v1/resources/{id}` | `SCOPE_read` (ADMIN only) | Get a resource (owner-checked) |
| `POST` | `/api/v1/resources` | `SCOPE_write` (ADMIN only) | Create a new resource |
| `PUT` | `/api/v1/resources/{id}` | `SCOPE_write` (ADMIN only) | Update a resource (owner-checked) |
| `DELETE` | `/api/v1/resources/{id}` | `SCOPE_write` (ADMIN only) | Delete a resource (owner-checked) |
| `GET` | `/api/v1/admin/resources` | `ROLE_ADMIN` | Admin-only: list all resources across all owners |

**USER tokens** (from the `users` table) have no authorities. They can access public endpoints and `/api/v1/me` but receive `403 Forbidden` on any endpoint requiring `SCOPE_*` or `ROLE_*`.

**ADMIN tokens** (from the `admin_users` table) carry `ROLE_ADMIN`, group-based `ROLE_ADMIN_GROUP_*` authorities, and `SCOPE_read`/`SCOPE_write`. They can access all resource endpoints and admin endpoints.

---

## Database Design

### Databases and Schemas

Each service has its own PostgreSQL database with a dedicated schema, isolated credentials, and independent Flyway migrations:

| Service | Database | Schema | Owner | Migration Files |
|---------|:---------|:-------|:------|:----------------|
| auth-server | `authdb` | `auth` | `auth_user` | 2 |
| iam-server | `iamdb` | `iam` | `iam_user` | 5 |
| resource-server | `resourcedb` | `resource_app` | `resource_user` | 1 |
| gateway | _none_ | _none_ | _none_ | _none_ |

Database initialization happens at PostgreSQL container startup via `docker/postgres/init/01-create-databases.sql`. Flyway then manages all schema creation and migrations within each database.

### Entity-Relationship Overview

**iam-server (`iam` schema):**

```text
users                          admin_users                   admin_groups
├── id (UUID, PK)              ├── id (UUID, PK)             ├── id (SERIAL, PK)
├── email (UNIQUE)             ├── email (UNIQUE)            ├── name (UNIQUE)
├── username (UNIQUE, null)    ├── username (UNIQUE, null)   └── description
├── password_hash              ├── password_hash
├── first_name                 ├── first_name                admin_group_members
├── last_name                  ├── last_name                 ├── admin_user_id (FK → admin_users)
├── enabled                    ├── enabled                   └── group_id (FK → admin_groups)
├── email_verified             ├── credentials_changed_at
├── credentials_changed_at     ├── created_at
├── created_at                 ├── updated_at
├── updated_at                 └── last_login_at             user_password_reset_tokens
└── last_login_at                                            ├── id (BIGSERIAL, PK)
                                   admin_password_reset_tokens  ├── user_id (FK → users)
                                   ├── id (BIGSERIAL, PK)       ├── jti (UNIQUE)
                                   ├── admin_user_id (FK)        ├── expires_at
                                   ├── jti (UNIQUE)              ├── used
                                   ├── expires_at                └── created_at
                                   ├── used
                                   └── created_at
```

**Key design decisions:**
- **Separate `users` and `admin_users` tables** (not a discriminator column): Each account type evolves independently. No nullable columns or check constraints.
- **Same email can exist in both tables**: A person can hold a regular user account and an admin account with the same email. They are distinct identities with separate passwords.
- **UUID primary keys**: Both `users.id` and `admin_users.id` use `gen_random_uuid()` to guarantee globally unique subject identifiers across both tables. The `sub` claim in JWTs is always a UUID.
- **Login by email with user type selector**: The login form requires the user to explicitly choose "User" or "Admin". IAM queries only the matching table.

**auth-server (`auth` schema):**

Standard Spring Authorization Server JDBC schema:
- `oauth2_registered_client` — OAuth2 client registrations
- `oauth2_authorization` — authorization codes, access tokens, refresh tokens, state
- `oauth2_authorization_consent` — user consent records
- `spring_session` / `spring_session_attributes` — JDBC-backed HTTP sessions

**resource-server (`resource_app` schema):**

- `user_resources` — domain resources with `owner_subject`, `name`, `data`, timestamps

### Flyway Migrations

Each module manages its own schema through Flyway. Migration files live in `<module>/src/main/resources/db/migration/`.

```
auth-server/src/main/resources/db/migration/
├── V1__authorization_server_schema.sql
└── V2__seed_oauth_clients.sql

iam-server/src/main/resources/db/migration/
├── V1__users_schema.sql
├── V2__admin_users_schema.sql
├── V3__seed_admin_groups.sql
├── V4__seed_default_admin.sql
└── V5__password_reset_tokens.sql

resource-server/src/main/resources/db/migration/
└── V1__resource_schema.sql
```

To add a new migration, create `V{n}__description.sql` in the appropriate module's migration directory. Flyway runs pending migrations automatically on startup.

---

## Security Design

### Password Hashing

All user and admin passwords are hashed with **Argon2id**, the current OWASP-recommended algorithm:

| Parameter | Regular Users | Admin Users |
|-----------|---------------|-------------|
| Algorithm | Argon2id | Argon2id |
| Memory | 64 MiB (65,536 KiB) | 128 MiB (131,072 KiB) |
| Iterations | 3 | 4 |
| Parallelism | 4 | 4 |
| Salt length | 16 bytes | 16 bytes |
| Hash length | 32 bytes | 32 bytes |
| Min password length | 8 characters | 14 characters |

OAuth2 client secrets (stored in the auth server) use **BCrypt** — they are machine-generated high-entropy values, not human-chosen passwords.

### JWT Token Claims

Access tokens are JWS-encoded (three-part `header.payload.signature`) with `typ: at+jwt` per RFC 9068.

| Claim | Source | Present on |
|-------|--------|------------|
| `sub` | IAM user ID (UUID) or client ID | All tokens |
| `jti` | Auth server generated UUID | All tokens |
| `email` | IAM email | User tokens only |
| `preferred_username` | IAM username or email local-part | User tokens only |
| `given_name` | IAM firstName | User tokens only |
| `family_name` | IAM lastName | User tokens only |
| `client_id` | OAuth2 client ID | All tokens |
| `aud` | Allowed audience (`["resource-server"]`) | All tokens |
| `scope` | Granted OAuth2 scopes | All tokens |
| `user_type` | `"USER"` or `"ADMIN"` | User tokens only |
| `roles` | IAM roles (ADMIN only) | Admin tokens only |
| `iss` | Auth server issuer URL | All tokens |
| `exp` | Expiration time | All tokens |
| `iat` | Issued-at time | All tokens |

**Authority model:**

| `user_type` | Source Table | Authorities | Access |
|-------------|-------------|-------------|--------|
| `USER` | `users` | _none_ (empty) | Public endpoints, `/api/v1/me/**` |
| `ADMIN` | `admin_users` | `ROLE_ADMIN` + `ROLE_ADMIN_GROUP_<name>` per group + `SCOPE_read` + `SCOPE_write` | All endpoints |

### Audience Enforcement

- Access tokens include `aud: ["resource-server"]`
- The gateway validates audience per route: `/api/**` requires `resource-server` audience
- The resource server independently validates audience on every request
- Tokens with wrong audience are rejected with `401 Unauthorized`

### Refresh Token Rotation & Revocation

- Refresh tokens are rotated on every use (`reuseRefreshTokens: false`)
- Password change or account disable revokes all refresh tokens for that user
- IAM calls `POST /internal/auth/revoke-user/{userId}` on the auth server after password reset, admin password change, and account disable/enable
- The auth server clears all `oauth2_authorization` rows for the principal

### IAM Internal API Protection

Internal endpoints (`/internal/**`) are protected by a shared `X-Internal-Token` header. The token value is configured via the `IAM_INTERNAL_TOKEN` environment variable. In production, this should be replaced with mTLS or a service mesh identity policy.

### Header Sanitation in Gateway

The `JwtHeaderEnrichmentFilter`:
1. **Strips** all inbound `X-Authenticated-*` headers (prevents header forgery)
2. **Sets** fresh `X-Authenticated-*` headers from the validated JWT claims
3. **Preserves** the `Authorization: Bearer <token>` header for downstream JWT validation
4. **Bypasses** public paths (no enrichment needed)
5. **Returns 401** if no valid authentication is present on protected paths

Resource servers must validate JWTs independently. The convenience headers are hints, not the security authority.

### CORS Policy

- Local/dev: allows `http://localhost:3000` (typical SPA dev server) and `http://localhost:9080`
- Allowed methods: `GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`
- Allowed headers: `Authorization`, `Content-Type`, `X-Request-Id`
- `Access-Control-Allow-Credentials: true` for authorization code flow (browser sends session cookies)
- Production: allow only specific frontend origins; never use wildcard with credentials

### Threat Mitigations

| Threat | Mitigation |
|--------|-----------|
| Brute-force credential guessing | Rate limiting on login and token endpoints (pluggable); audit log of failures |
| Token theft (access token) | Short TTL (5–30 min); audience restriction; TLS everywhere |
| Token theft (refresh token) | Rotation on use; revocation on password change; bound to client |
| Forged identity headers | Gateway strips inbound `X-Authenticated-*`; resource servers validate JWT directly |
| Client secret extraction from SPA | Public clients for browsers; no long-lived secrets in client-side code |
| Redirect URI manipulation | Exact URI matching; PKCE `S256` required for all authorization code clients |
| Signing key compromise | Key rotation procedure; emergency revocation; audit log of key operations |
| SQL injection | JPA parameterized queries; Flyway migrations are reviewed |
| Database credential leak | Per-service credentials; no secrets in logs or repository |
| IAM down (DoS) | Auth-server circuit breaker fails closed; OIDC/JWKS remain available |

---

## Authorization Patterns

The resource server demonstrates these authorization patterns as a reference for new domain services:

### 1. Method-Level Scope Check

```kotlin
@PreAuthorize("hasAuthority('SCOPE_write')")
fun createResource(...): ResponseEntity<...>
```

Only ADMIN tokens with the `write` scope can create resources. USER tokens have no `SCOPE_*` authorities and receive `403`.

### 2. Method-Level Role Check

```kotlin
@PreAuthorize("hasRole('ADMIN')")
fun adminListAllResources(...): ResponseEntity<...>
```

Only ADMIN tokens with the `ROLE_ADMIN` authority can access admin endpoints.

### 3. Fine-Grained Group Check

```kotlin
@PreAuthorize("hasAnyRole('ADMIN_GROUP_USER_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
fun listUsers(...): ResponseEntity<...>
```

Admin endpoints are gated by specific group authorities.

### 4. Owner-Based Access Control

```kotlin
if (!authorizationChecker.canRead(requesterId, resource.ownerSubject, role)) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).build()
}
```

Resource owners can read/write/delete their own resources. Admins can access any resource. Regular users can only access their own.

### 5. URL-Level Path Security

```kotlin
.requestMatchers("/api/v1/public/**").permitAll()
.requestMatchers("/api/v1/me/**").authenticated()
.anyRequest().authenticated()
```

Public paths are configured at the HTTP security level. Everything else requires a valid token.

### 6. Composite Authority Converter

The `CompositeJwtGrantedAuthoritiesConverter` extracts both `SCOPE_*` and `ROLE_*` authorities from JWT claims. USER tokens have neither. ADMIN tokens get both from the `scope` and `roles` claims, plus an automated `ROLE_ADMIN` from the `user_type` claim.

---

## Configuration

### Environment Variables

#### Docker Compose

| Variable | Used By | Purpose |
|----------|---------|---------|
| `SPRING_PROFILES_ACTIVE` | All | Set to `docker` to load `application-docker.yml` |
| `SPRING_DATASOURCE_URL` | auth, iam, resource | PostgreSQL JDBC URL |
| `SPRING_DATASOURCE_USERNAME` | auth, iam, resource | Database user |
| `SPRING_DATASOURCE_PASSWORD` | auth, iam, resource | Database password |
| `DB_SCHEMA` | auth, iam, resource | Flyway/JPA default schema |
| `IAM_BASE_URL` | auth | IAM server URL for internal calls |
| `IAM_INTERNAL_TOKEN` | auth, iam | Shared secret for internal API protection |
| `AUTH_ISSUER` | gateway, resource | Expected `iss` claim in tokens |
| `AUTH_JWKS_URI` | gateway, resource | URL to fetch JWT signing public keys |
| `AUTH_SIGNING_KEY_PATH` | auth | Path to persisted signing key file |
| `EMAIL_ENABLED` | iam | Enable actual SMTP email sending |
| `EMAIL_FROM` | iam | From address for emails |
| `EMAIL_RESET_LINK_BASE` | iam | Base URL for password reset links |

#### Local Development

Each service's `application.yml` provides local defaults (pointing to `localhost`). Override with environment variables or an `.env` file. See `.env.example` for the full list:

```bash
# Database
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/iamdb
SPRING_DATASOURCE_USERNAME=iam_user
SPRING_DATASOURCE_PASSWORD=iam_pass

# Internal API
IAM_INTERNAL_TOKEN=dev-internal-token

# Auth
AUTH_ISSUER=http://localhost:9081
AUTH_JWKS_URI=http://localhost:9081/oauth2/jwks
```

### OAuth2 Registered Clients

Seeded in `auth-server/src/main/resources/db/migration/V2__seed_oauth_clients.sql`:

| Client ID | Grant Types | Scopes | Secret (plaintext) | Notes |
|-----------|-------------|--------|---------------------|-------|
| `web-client` | authorization_code, refresh_token | openid, profile, read, write | `secret` | Browser/SPA client; PKCE required; consent enabled |
| `service-client` | client_credentials | read, write | `service-secret` | Machine-to-machine testing |
| `gateway-client` | client_credentials | internal.gateway | `gateway-secret` | Future internal gateway use |

All secrets are stored as BCrypt hashes in the database. The plaintext values above are for local development only.

### Seeded Users

Seeded in `iam-server/src/main/resources/db/migration/V4__seed_default_admin.sql`:

| Email | Password | Type | Groups |
|-------|----------|------|--------|
| `admin@localhost` | `admin123` | ADMIN | FULL_ACCESS |

---

## Project Layout

```text
auth-platform/
├── settings.gradle.kts                  # Root Gradle settings (4 modules)
├── build.gradle.kts                     # Common config + plugin declarations
├── gradlew / gradlew.bat                # Gradle wrapper
├── gradle/
│   ├── libs.versions.toml               # Version catalog
│   └── wrapper/
├── docker-compose.yml                   # Full-stack orchestration
├── smoke-test.sh                        # End-to-end test script
├── docker/
│   └── postgres/init/
│       └── 01-create-databases.sql      # PostgreSQL init script
│
├── auth-server/                         # OAuth2 Authorization Server
│   ├── build.gradle.kts
│   ├── Dockerfile
│   └── src/main/
│       ├── kotlin/com/zhouij/authplatform/authserver/
│       │   ├── AuthServerApplication.kt
│       │   ├── auth/
│       │   │   ├── IamAuthenticationProvider.kt
│       │   │   ├── IamClient.kt
│       │   │   ├── IamLoginAuthenticationToken.kt
│       │   │   └── IamPrincipal.kt
│       │   ├── config/
│       │   │   ├── AuthorizationServerConfig.kt
│       │   │   ├── JwkConfig.kt
│       │   │   └── SecurityConfig.kt
│       │   └── controller/
│       │       ├── InternalController.kt
│       │       └── LoginController.kt
│       └── resources/
│           ├── application.yml
│           ├── application-docker.yml
│           ├── db/migration/
│           │   ├── V1__authorization_server_schema.sql
│           │   └── V2__seed_oauth_clients.sql
│           └── templates/
│               └── login.html
│
├── iam-server/                          # Identity & Access Management
│   ├── build.gradle.kts
│   ├── Dockerfile
│   └── src/main/
│       ├── kotlin/com/zhouij/authplatform/iam/
│       │   ├── IamServerApplication.kt
│       │   ├── config/SecurityConfig.kt
│       │   ├── controller/
│       │   │   ├── AdminController.kt
│       │   │   ├── AuthController.kt
│       │   │   └── InternalAuthController.kt
│       │   ├── domain/
│       │   │   ├── AdminGroupEntity.kt
│       │   │   ├── AdminGroupMemberEntity.kt
│       │   │   ├── AdminPasswordResetTokenEntity.kt
│       │   │   ├── AdminUserEntity.kt
│       │   │   ├── UserEntity.kt
│       │   │   └── UserPasswordResetTokenEntity.kt
│       │   ├── repository/
│       │   │   ├── AdminGroupRepository.kt
│       │   │   ├── AdminPasswordResetTokenRepository.kt
│       │   │   ├── AdminUserRepository.kt
│       │   │   ├── UserPasswordResetTokenRepository.kt
│       │   │   └── UserRepository.kt
│       │   └── service/
│       │       ├── AdminUserService.kt
│       │       ├── PasswordResetService.kt
│       │       ├── PasswordService.kt
│       │       └── UserService.kt
│       └── resources/
│           ├── application.yml
│           ├── application-docker.yml
│           └── db/migration/
│               ├── V1__users_schema.sql
│               ├── V2__admin_users_schema.sql
│               ├── V3__seed_admin_groups.sql
│               ├── V4__seed_default_admin.sql
│               └── V5__password_reset_tokens.sql
│
├── gateway/                             # API Gateway (stateless)
│   ├── build.gradle.kts
│   ├── Dockerfile
│   └── src/main/
│       ├── kotlin/com/zhouij/authplatform/gateway/
│       │   ├── AuthGatewayApplication.kt
│       │   ├── config/SecurityConfig.kt
│       │   └── filter/JwtHeaderEnrichmentFilter.kt
│       └── resources/
│           └── application.yml
│
└── resource-server/                     # Reference Domain Service
    ├── build.gradle.kts
    ├── Dockerfile
    └── src/main/
        ├── kotlin/com/zhouij/authplatform/resourceserver/
        │   ├── ResourceServerApplication.kt
        │   ├── config/
        │   │   ├── CompositeJwtGrantedAuthoritiesConverter.kt
        │   │   └── SecurityConfig.kt
        │   ├── controller/DemoController.kt
        │   ├── domain/UserResourceEntity.kt
        │   ├── repository/UserResourceRepository.kt
        │   └── service/AuthorizationChecker.kt
        └── resources/
            ├── application.yml
            ├── application-docker.yml
            └── db/migration/
                └── V1__resource_schema.sql
```

---

## Development Guide

### Building

```bash
# Compile all modules
./gradlew compileKotlin

# Compile a specific module
./gradlew :iam-server:compileKotlin

# Full build (compile + test)
./gradlew build

# Clean build
./gradlew clean build

# List all available tasks
./gradlew tasks

# Show project structure
./gradlew projects
```

### Running Tests

```bash
# Run all tests
./gradlew test

# Run tests for a specific module
./gradlew :iam-server:test
./gradlew :auth-server:test
./gradlew :resource-server:test
./gradlew :gateway:test

# Run a specific test class
./gradlew :iam-server:test --tests "com.iam.IamServerApplicationTests"

# Run with verbose output
./gradlew test --info
```

**Test infrastructure:**
- `contextLoads()` tests verify Spring context wiring
- DB-backed module tests use Testcontainers (`postgres:16-alpine`) for database isolation
- Gateway tests use `WebTestClient` for reactive endpoint testing
- Resource server tests use `spring-security-test` JWT support

**Smoke test (requires Docker):**

```bash
docker compose up --build -d
# Wait for all services to be healthy (~60–90s)
./smoke-test.sh
```

The smoke test covers 12 scenarios:
1. OIDC discovery document
2. JWKS endpoint returns keys
3. Client credentials token issuance
4. Gateway public endpoint (no auth)
5. Gateway authenticated endpoint (with token)
6. Gateway protected endpoint returns 401 without token
7. User registration
8. User login
9. Wrong password returns 401
10. Duplicate registration returns 409
11. Internal API rejects invalid token
12. Admin endpoint returns 403 for USER token

### Adding a Flyway Migration

1. Create a new SQL file in the appropriate module: `<module>/src/main/resources/db/migration/V{n}__description.sql`
2. Use the next sequential version number
3. Write idempotent DDL (Flyway runs each migration exactly once)
4. Restart the service — Flyway runs pending migrations automatically

Example:
```sql
-- iam-server/src/main/resources/db/migration/V6__add_email_verification_token.sql
ALTER TABLE users ADD COLUMN verification_token VARCHAR(255);
ALTER TABLE users ADD COLUMN verification_token_expires_at TIMESTAMPTZ;
```

### Adding a New Domain Service

1. Create a new Gradle module: add `include("my-service")` to `settings.gradle.kts`
2. Create `my-service/build.gradle.kts` with dependencies (use the Spring Boot platform BOM)
3. Add Flyway migrations for your schema
4. Add a gateway route in `gateway/src/main/resources/application.yml`
5. If the new service needs JWT validation, add `spring-boot-starter-oauth2-resource-server` and configure issuer/JWKS URI
6. Add the service to `docker-compose.yml` with appropriate healthchecks and dependency ordering

---

## Deployment

### Docker Images

Each module has a multi-stage `Dockerfile`:

```dockerfile
FROM gradle:8.14-jdk21 AS build
WORKDIR /app
COPY . .
RUN gradle :<module>:bootJar --no-daemon -x test

FROM eclipse-temurin:21-jre-alpine
# ... non-root user, copy JAR, expose port
```

Images are built with the repository root as build context (required for Gradle multi-project builds).

### Docker Compose

`docker compose up --build -d` starts the full stack:

1. **postgres** — PostgreSQL 16 with three databases
2. **iam-server** — starts after postgres is healthy; Flyway runs on startup
3. **auth-server** — starts after iam-server is healthy; seeds OAuth2 clients
4. **resource-server** — starts after auth-server is healthy
5. **gateway** — starts last; begins accepting traffic immediately

All services restart automatically (`unless-stopped`). Healthchecks monitor liveness via `/actuator/health/liveness`.

### Production Considerations

Before deploying to production:

1. **Secrets**: Never commit production secrets. Use Kubernetes Secrets, HashiCorp Vault, AWS Secrets Manager, or SOPS-encrypted files. Required secrets:
   - Database passwords (for all three databases)
   - OAuth2 client secrets (BCrypt hashed in the database, plaintext from environment)
   - IAM internal token (replace with mTLS)
   - Signing private key (RSA 2048+, persisted, with key rotation plan)

2. **Signing keys**: The auth server generates ephemeral RSA keys on startup. For production, mount a persisted JWK from a secret:
   ```yaml
   AUTH_SIGNING_KEY_PATH: /run/secrets/auth-signing-key.jwk
   ```

3. **TLS**: Put TLS at the edge (load balancer or reverse proxy). Set `Secure: true` on session cookies.

4. **Issuer URL**: Set `AUTH_ISSUER` to the public HTTPS URL (e.g., `https://auth.example.com`). This is embedded in every token and validated by all services.

5. **Session store**: The auth server uses JDBC-backed sessions (in `authdb`). This survives restarts. For multi-replica deployments, ensure all replicas share the same database or switch to Redis via `spring-session-data-redis`.

6. **Email**: Set `EMAIL_ENABLED=true` and configure SMTP for password reset emails. Without it, reset links are logged to stdout only.

7. **Rate limiting**: Add a `RequestRateLimiter` filter in the gateway backed by Redis. Target: 30 req/min per client on `/oauth2/token`, 10 req/min per IP on `/login`, 5 req/10min per IP on `/api/auth/register`.

8. **Audit logging**: Enable structured JSON logging. Never log passwords, client secrets, full access tokens, refresh tokens, or authorization codes.

---

## Observability

All services expose:

| Endpoint | Purpose |
|----------|---------|
| `GET /actuator/health` | Combined health |
| `GET /actuator/health/liveness` | Liveness probe (process health) |
| `GET /actuator/health/readiness` | Readiness probe (dependency health) |
| `GET /actuator/metrics` | Micrometer metrics |

**Liveness** fails only when the process is unhealthy and should be restarted. **Readiness** fails when required dependencies (database, IAM, JWKS endpoint) are unavailable.

**Key metrics** captured at minimum:
- HTTP request counts, latency, and status by service and endpoint
- Auth-server token issuance success/failure by grant type and client ID
- Login success/failure counts by reason class
- IAM internal validation latency and failure counts
- Gateway route latency and upstream error counts
- Resource-server authorization failures by endpoint group
- Database connection pool usage
- Circuit-breaker state transitions for IAM calls

---

## Extending the System

| Feature | Status | How to Add |
|---------|--------|------------|
| Email verification | Deferred | Add `verification_token` column to `users`, send verification email on registration |
| MFA / WebAuthn | Deferred | Add `mfa_secret` / `webauthn_credentials` tables, extend login flow in IAM |
| Dynamic OAuth client registration | Deferred | Add admin API in auth-server, or enable RFC 7591 dynamic registration endpoint |
| Service discovery | Deferred | Add Eureka/Consul; change gateway URIs to `lb://service-name` |
| Redis-backed rate limiting | Deferred | Add `RequestRateLimiter` filter in gateway backed by Redis |
| CI/CD pipeline | Deferred | GitHub Actions: `./gradlew build` with Testcontainers, build and push Docker images |
| Audit event persistence | Deferred | Publish audit events to a persistent store (database table, Kafka topic, or log aggregation) |
| Distributed tracing | Deferred | Add Micrometer Tracing + OpenTelemetry; propagate trace IDs across service boundaries |

---

## License

This project is provided as a reference implementation. Adapt and extend it for your own use.
