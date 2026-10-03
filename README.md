# ATS — Auth Token Server

A standalone authentication service written in Go that issues short-lived JWT access tokens and stateful refresh tokens. Built to demonstrate **backend engineering + security + distributed systems + Go mastery** through a single, well-scoped service that does one thing correctly.

---

## What It Does

- Issues **RS256-signed JWT access tokens** (short-lived, e.g. 15 minutes)
- Issues **opaque refresh tokens** stored durably in PostgreSQL
- Rotates refresh tokens on every use (old token revoked atomically, new token issued)
- Revokes tokens immediately via a write-through Redis cache with Postgres as the authoritative source of truth
- Exposes a **JWKS endpoint** so downstream services validate tokens locally — no round-trip to ATS
- Supports two grant flows:
  - **Password grant** — human users (`email` + `password`)
  - **Client credentials grant** — service accounts (`client_id` + `client_secret`) for M2M

---

## Data Authority Model

| Layer | Role | Disposable? |
|-------|------|-------------|
| **PostgreSQL** | Durable source of truth — every token, user, and service account record | No |
| **Redis** | Write-through revocation cache — fast-path for "is this token revoked?" | **Yes** — flush it anytime, correctness is preserved |

Redis is **never** the sole decision-maker. A `revoked=true` from Redis is trusted for a fast reject. A miss or error falls through to Postgres. Expiry is always checked against the Postgres record.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/token` | Issue access + refresh tokens (password or client credentials grant) |
| `POST` | `/auth/refresh` | Rotate refresh token, issue new access token |
| `POST` | `/auth/revoke` | Revoke a refresh token |
| `GET` | `/.well-known/jwks.json` | Public key document for downstream JWT validation |
| `GET` | `/health` | Liveness — is the process alive? |
| `GET` | `/ready` | Readiness — is Postgres + Redis reachable? |

### POST /auth/token — Password Grant
```json
// Request
{
  "grant_type": "password",
  "email": "user@example.com",
  "password": "secret"
}

// Response 200
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<opaque>",
  "scope": "read write"
}
```

### POST /auth/token — Client Credentials Grant
```json
// Request
{
  "grant_type": "client_credentials",
  "client_id": "svc-payments",
  "client_secret": "secret"
}
```

### POST /auth/refresh
```json
// Request
{ "refresh_token": "<opaque>" }

// Response 200 — new access token + rotated refresh token
{
  "access_token": "<new-jwt>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<new-opaque>",
  "scope": "read write"
}
```

### POST /auth/revoke
```json
// Request
{ "refresh_token": "<opaque>" }

// Response 200
{}
```

### Error Shape
All errors follow a consistent envelope:
```json
{
  "error": "invalid_grant",
  "error_description": "refresh token has been revoked"
}
```

---

## Token Design

**Access Token (JWT)**

| Claim | Value |
|-------|-------|
| `sub` | User or service account UUID |
| `sub_type` | `user` or `service_account` |
| `scope` | Space-separated list of granted scopes |
| `jti` | Unique token ID (UUID) |
| `iss` | `https://ats.backendbytecraft.com` |
| `iat` / `exp` | Issued at / expiry |

Signed with **RS256**. The `kid` header matches the key ID in the JWKS endpoint.

**Refresh Token**

- 32 cryptographically random bytes, base64url-encoded (returned to client)
- SHA-256 hash of the raw value stored in Postgres (`refresh_tokens.token_hash`)
- Never stored in plaintext anywhere

---

## Refresh Token Rotation Flow

```
POST /auth/refresh
        │
        ▼
Redis: IsRevoked?
        │
   revoked=true ──────────────────► 401 (fast-path, no DB call)
        │
  miss / error / not revoked
        │
        ▼
BEGIN Postgres transaction
        │
SELECT token FOR UPDATE  ◄── row lock prevents concurrent rotation race
        │
   not found ───────────────────► 401
        │
   revoked=true ────────────────► 401
        │
   expires_at passed ───────────► 401
        │
       valid
        │
UPDATE old token SET revoked=true
INSERT new refresh token
COMMIT
        │
        ▼
Mint + return new access + refresh tokens
        │
        ▼
Redis SetRevoked (best-effort, post-response)
```

---

## Stack

| Concern | Choice |
|---------|--------|
| Language | Go 1.26 |
| HTTP router | `go-chi/chi/v5` |
| JWT | `golang-jwt/jwt/v5` |
| SQL | `jmoiron/sqlx` + `jackc/pgx/v5` |
| Cache | `redis/go-redis/v9` |
| Password hashing | `bcrypt` (`golang.org/x/crypto`) |
| Config | Environment variables only (12-factor) |
| Logging | `github.com/rs/zerolog` (zero-allocation structured JSON) |
| Database | PostgreSQL 16 |
| Cache store | Redis 7 |

---

## Running Locally

### Prerequisites
- Docker + Docker Compose

### Start the full stack
```bash
cp .env.example .env
# Edit .env — set RSA_PRIVATE_KEY_PEM (see Key Generation below)
docker compose up
```

ATS listens on `http://localhost:8080`.

### Key Generation
```bash
# Generate RSA private key
openssl genrsa -out private.pem 2048

# Export as single-line env var
RSA_PRIVATE_KEY_PEM=$(awk 'NF {sub(/\r/, ""); printf "%s\\n", $0}' private.pem)
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_DSN` | yes | — | Postgres DSN e.g. `postgres://ats:secret@localhost:5432/ats?sslmode=disable` |
| `REDIS_ADDR` | yes | — | Redis address e.g. `localhost:6379` |
| `REDIS_PASSWORD` | no | `""` | Redis auth password |
| `RSA_PRIVATE_KEY_PEM` | yes | — | PEM-encoded RSA private key (PKCS1 or PKCS8) |
| `ACCESS_TOKEN_TTL` | no | `15m` | Access token lifetime (Go duration string) |
| `REFRESH_TOKEN_TTL` | no | `168h` | Refresh token lifetime (7 days) |
| `SERVER_ADDR` | no | `:8080` | HTTP listen address |
| `BCRYPT_COST` | no | `12` | bcrypt work factor |

---

## Project Structure

```
ats/
├── cmd/ats/main.go          # Entry point — wires all components, starts server
├── internal/
│   ├── config/              # Env-var config loader
│   ├── keys/                # RSA key parsing + JWKS builder
│   ├── store/               # PostgreSQL repositories (users, service accounts, tokens)
│   ├── cache/               # Redis write-through revocation cache
│   ├── token/               # JWT minting + opaque refresh token generation
│   ├── handler/             # HTTP handlers + Chi router
│   └── middleware/          # Request logging middleware
├── migrations/              # Plain SQL migration files
├── Dockerfile               # Multi-stage build (coming in Sprint 3)
├── docker-compose.yml       # Local dev stack: ATS + Postgres + Redis (coming in Sprint 3)
└── .env.example             # All env vars documented (coming in Sprint 3)
```

---

## Downstream Integration

Downstream Go services validate access tokens **locally** using the JWKS endpoint — no call to ATS on every request.

```go
// Fetch JWKS once at startup (or on kid miss)
// GET http://ats:8080/.well-known/jwks.json

// Validate token locally
token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
    // look up the public key by t.Header["kid"] from your cached JWKS
    return publicKey, nil
})
```

Scopes are embedded in the `scope` claim (space-separated). Downstream services enforce them locally — no authorization call to ATS required.

---

## What Is Deliberately Out of Scope (v1.0.0)

| Feature | Why Deferred |
|---------|-------------|
| Token introspection endpoint | Downstream services use local JWKS validation |
| Rate limiting | Separate concern; design decision on state location needed |
| RSA key rotation | Operationally complex; multi-`kid` JWKS serving |
| Admin API | Requires its own auth model |
| Anomaly detection / risk scoring | ML/data pipeline — entirely separate problem space |

## Status

Currently in active development — **Sprint 1 of 3**.

| Sprint | Theme | Status |
|--------|-------|--------|
| Sprint 1 | Foundation — config, keys, schema | 🔄 In progress |
| Sprint 2 | Core logic — store, cache, token | ⏳ Pending |
| Sprint 3 | Integration + ops — handlers, Docker, tests | ⏳ Pending |
