# rw3iss Authentication Server

📚 **Full documentation**: [auth-docs.rw3iss.com](https://auth-docs.rw3iss.com/auth-server/overview/)

A standalone, enterprise-level, multi-tenant authentication server written in Go for the rw3iss auction platform. This server handles user registration, authentication, organization management, role-based access control (RBAC), and SSO integration.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Features](#features)
- [System Design](#system-design)
- [Getting Started](#getting-started)
- [Docker Setup](#docker-setup)
- [Running Tests](#running-tests)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Database Schema](#database-schema)
- [Security](#security)
- [Deployment](#deployment)
- [Further Documentation](#further-documentation)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              rw3iss Auth Server                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         API Layer (HTTP)                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │   Auth      │  │   User      │  │   Org       │  │   Role      │  │   │
│  │  │  Handler    │  │  Handler    │  │  Handler    │  │  Handler    │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                       Middleware Layer                                │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │   Auth      │  │   RBAC      │  │   Rate      │  │   CORS      │  │   │
│  │  │ Middleware  │  │ Middleware  │  │  Limiter    │  │ Middleware  │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        Service Layer                                  │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │   Auth      │  │   User      │  │   Org       │  │   Role      │  │   │
│  │  │  Service    │  │  Service    │  │  Service    │  │  Service    │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│  ┌────────────────────────────┐  ┌────────────────────────────┐             │
│  │      Auth Module           │  │      Email Module          │             │
│  │  ┌──────────┐ ┌─────────┐  │  │  ┌──────────────────────┐  │             │
│  │  │   JWT    │ │   SSO   │  │  │  │   SMTP Service       │  │             │
│  │  │ Service  │ │ Manager │  │  │  │   (Verification,     │  │             │
│  │  └──────────┘ └─────────┘  │  │  │   Reset, Invite)     │  │             │
│  └────────────────────────────┘  │  └──────────────────────┘  │             │
│                                  └────────────────────────────┘             │
│                                    │                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        Cache Layer                                   │   │
│  │  ┌──────────────────────────────────────────────────────────────┐    │   │
│  │  │   Redis Token Cache (validated tokens, blacklist, rate limit) │    │   │
│  │  └──────────────────────────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                       Repository Layer                                │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │   User      │  │   Org       │  │   Role      │  │   Token     │  │   │
│  │  │   Repo      │  │   Repo      │  │   Repo      │  │   Repo      │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                    ┌───────────────┴───────────────┐                         │
│                    │                               │                         │
│           ┌────────┴────────┐             ┌───────┴───────┐                  │
│           │   PostgreSQL    │             │     Redis     │                  │
│           │    Database     │             │     Cache     │                  │
│           └─────────────────┘             └───────────────┘                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Features

### Authentication
- **Local Authentication**: email/password with three registration modes (`register` / `register_or_login` / `register_or_return`)
- **SSO Integration**: Google, Apple, Microsoft, GitHub, and custom OAuth providers — with redirect-URL allowlist and Redis-backed atomic state validation
- **JWT Tokens**: HS256 access + refresh, with `org_id`, `app_id`, `app_code`, and per-user `tv` (token-version) claims; purpose-derived secrets for password-reset and email-verification tokens
- **Session Management**: track and terminate active sessions
- **Remember Me**: extended session support
- **Two-Factor Authentication**: schema-prepared (not yet wired)
- **Cognito auto-migrate**: optional drop-in adapter (`pkg/migration/cognito`) consults a legacy Cognito pool when an email isn't in the internal store

### Multi-Tenancy + App-Scoping
- **Organizations**: users belong to N organizations
- **Apps**: tokens are scoped to a registered consuming app (`app_id` claim); per-user `user_apps` membership controls access
- **User pools / namespaces** (migration 017): each app can optionally declare a *write* pool (`registration_namespace`) new users land in, and a set of *read* pools (`read_namespaces`) it authenticates against — so an app can own its own user pool yet still recognize existing users from shared pools (no duplicate identity). Email is unique per `(namespace, email)`. Unconfigured apps use the single `default` pool — fully backwards-compatible. See [`docs/USER_POOLS.md`](./docs/USER_POOLS.md).
- **Org self-service endpoints**: `/orgs/{orgId}/*` for users with `org:*` permissions; separate from the platform-admin `/admin/organizations/*`
- **Invitation System**: invite via code or email link
- **Custom SSO per org**: schema-prepared

### Role-Based Access Control (RBAC)
- **Role hierarchy** (lower number = more privileged):
  - `system_admin` (0) — platform owner; bypasses every gate
  - `super_admin` (5) — cross-org data administrator; can't reach platform internals
  - `org_admin` (10), `org_manager` (20), `org_member` (80), `base_user` (100)
- **Permission namespaces**: `admin-*` for platform routes (system_admin only); `org:*` for org self-service (org_admin & up); service-self-registered slices (`POST /admin/permissions/register`)
- **Single-use reset/verify tokens** with purpose claim + audience separation
- **Refresh-token family rotation** with reuse detection (RFC 6819)
- **Per-user token-version** for immediate cross-replica logout-all

### Caching (Redis)
- **Token Validation Cache**: parsed JWT claims cached by token hash, with token-version re-check on every hit
- **Token Blacklist**: revoked `jti`s for immediate invalidation
- **Token-Version Counter**: per-user `auth:user_tv:{user_id}` for cross-replica logout-all
- **SSO State Store**: atomic GETDEL-backed state (Redis 6.2+); in-memory fallback when Redis is down
- **Idempotency Cache**: 5-min cached response replay on `Idempotency-Key` header
- **Per-IP and Per-Account Rate Limit**: Redis-backed; per-IP falls open in-memory when Redis is down
- **Graceful Fallback**: server boots and serves when Redis is unavailable; affected features (cache, idempotency, token-version) degrade silently

### Security (audit-fixed)
- **Password Hashing**: bcrypt with **honored** configurable cost (was previously ignored), max-length cap to bound CPU per login
- **JWT Validation**: enforces `aud`, `iss`, leeway, algorithm allowlist; distinct purpose-derived secrets for reset/verify tokens
- **Trusted-Proxy XFF**: `X-Forwarded-For` honored only from configured CIDRs; otherwise the remote address wins
- **CORS Hardening**: `*` + credentials no longer co-allowed; production refuses `CORS_ORIGINS=*` at boot
- **SQL Injection-Safe Sort**: per-repo allowlists on every `ORDER BY` interpolation
- **Body-Size Limit**: 5 MB default with a 15 MB ceiling for upload endpoints
- **Idempotency Keys** + **HttpOnly Cookie + CSRF** middlewares
- **Audit Log**: async writer to `audit_log` table (login.*, password.*, logout.all, refresh.reuse_detected, user.migrated_from_legacy)
- **Structured Logging**: slog JSON in production with `request_id` + `user_id` propagated through context
- **Background Jobs**: managed cleanup of expired tokens/sessions/reset/verify rows, exposed via `/admin/jobs`
- **Account Lockout** + **per-account rate limit** (sliding window keyed on sha256(email))
- **Security Headers**: nosniff, frame-deny, referrer policy, no-store cache control

## System Design

### Entity Relationship Diagram

```
┌──────────────────────┐
│        User          │
├──────────────────────┤
│ id                   │
│ email                │
│ password_hash        │
│ first_name           │
│ last_name            │
│ status               │
│ auth_provider        │
└──────────┬───────────┘
           │
           │ 1:N
           ▼
┌──────────────────────┐       ┌──────────────────────┐
│  UserAuthProvider    │       │    UserBaseRole      │
├──────────────────────┤       ├──────────────────────┤
│ user_id              │       │ user_id              │
│ provider             │       │ role_id              │
│ provider_user_id     │       │ assigned_at          │
└──────────────────────┘       └──────────┬───────────┘
                                          │
           ┌──────────────────────────────┼──────────────────────────────┐
           │                              │                              │
           ▼                              ▼                              ▼
┌──────────────────────┐       ┌──────────────────────┐       ┌──────────────────────┐
│ OrganizationMember   │       │        Role          │       │     Permission       │
├──────────────────────┤       ├──────────────────────┤       ├──────────────────────┤
│ id                   │       │ id                   │       │ id                   │
│ user_id              │       │ code                 │       │ code                 │
│ organization_id      │       │ name                 │       │ resource             │
│ status               │       │ type (system/custom) │       │ action               │
│ joined_at            │       │ is_org_role          │       │ category             │
└──────────┬───────────┘       │ organization_id      │       └──────────────────────┘
           │                   └──────────┬───────────┘                 ▲
           │                              │                              │
           │ N:M                          │ N:M                          │
           ▼                              ▼                              │
┌──────────────────────┐       ┌──────────────────────┐                 │
│ OrgMemberRole        │       │   RolePermission     │─────────────────┘
├──────────────────────┤       ├──────────────────────┤
│ membership_id        │       │ role_id              │
│ role_id              │       │ permission_id        │
│ assigned_by          │       └──────────────────────┘
└──────────────────────┘

           │
           │ N:1
           ▼
┌──────────────────────┐
│    Organization      │
├──────────────────────┤
│ id                   │
│ name                 │
│ slug                 │
│ owner_id             │
│ status               │
│ sso_enabled          │
│ sso_config           │
└──────────────────────┘
```

### Authentication Flow

```
                                    Registration Flow
┌────────┐                  ┌────────┐                  ┌────────┐
│ Client │                  │  Auth  │                  │Database│
└───┬────┘                  │ Server │                  └───┬────┘
    │                       └───┬────┘                      │
    │ POST /register            │                           │
    │ {email, password,         │                           │
    │  firstName, lastName,     │                           │
    │  ?inviteCode}             │                           │
    │──────────────────────────►│                           │
    │                           │ Validate & Hash Password  │
    │                           │──────────────────────────►│
    │                           │ Create User               │
    │                           │──────────────────────────►│
    │                           │ Assign Base Role          │
    │                           │──────────────────────────►│
    │                           │                           │
    │                           │ If inviteCode present:    │
    │                           │ - Get Invitation          │
    │                           │ - Create Membership       │
    │                           │ - Assign Org Roles        │
    │                           │──────────────────────────►│
    │                           │                           │
    │                           │ Send Verification Email   │
    │                           │─────────────►[Email]      │
    │                           │                           │
    │◄──────────────────────────│                           │
    │ {user, organization?,     │                           │
    │  verificationEmailSent}   │                           │
    │                           │                           │


                                      Login Flow
┌────────┐                  ┌────────┐                  ┌────────┐
│ Client │                  │  Auth  │                  │Database│
└───┬────┘                  │ Server │                  └───┬────┘
    │                       └───┬────┘                      │
    │ POST /login               │                           │
    │ {email, password,         │                           │
    │  ?organizationId,         │                           │
    │  ?rememberMe}             │                           │
    │──────────────────────────►│                           │
    │                           │ Get User by Email         │
    │                           │──────────────────────────►│
    │                           │◄──────────────────────────│
    │                           │ Verify Password           │
    │                           │ Check Lock Status         │
    │                           │                           │
    │                           │ If organizationId:        │
    │                           │   Get Membership          │
    │                           │   Get Org Roles           │
    │                           │──────────────────────────►│
    │                           │◄──────────────────────────│
    │                           │ Else:                     │
    │                           │   Get Base Roles          │
    │                           │──────────────────────────►│
    │                           │◄──────────────────────────│
    │                           │                           │
    │                           │ Collect Permissions       │
    │                           │ Generate Token Pair       │
    │                           │ Store Refresh Token       │
    │                           │ Create Session            │
    │                           │──────────────────────────►│
    │                           │                           │
    │◄──────────────────────────│                           │
    │ {user, organization?,     │                           │
    │  tokens: {accessToken,    │                           │
    │           refreshToken},  │                           │
    │  roles, permissions}      │                           │


                              Token Refresh Flow
┌────────┐                  ┌────────┐                  ┌────────┐
│ Client │                  │  Auth  │                  │Database│
└───┬────┘                  │ Server │                  └───┬────┘
    │                       └───┬────┘                      │
    │ POST /refresh             │                           │
    │ {refreshToken,            │                           │
    │  ?organizationId}         │                           │
    │──────────────────────────►│                           │
    │                           │ Validate Refresh Token    │
    │                           │ (JWT Signature)           │
    │                           │──────────────────────────►│
    │                           │ Check Token Not Revoked   │
    │                           │◄──────────────────────────│
    │                           │                           │
    │                           │ Revoke Old Token          │
    │                           │ Generate New Token Pair   │
    │                           │ Store New Refresh Token   │
    │                           │──────────────────────────►│
    │                           │                           │
    │◄──────────────────────────│                           │
    │ {accessToken,             │                           │
    │  refreshToken,            │                           │
    │  expiresIn}               │                           │
```

### SSO Flow

```
                                    SSO Login Flow
┌────────┐     ┌────────┐     ┌────────┐     ┌─────────┐
│ Client │     │  Auth  │     │  SSO   │     │Database │
└───┬────┘     │ Server │     │Provider│     └────┬────┘
    │          └───┬────┘     └───┬────┘          │
    │              │              │               │
    │ GET /sso/url │              │               │
    │ {provider,   │              │               │
    │  redirectUrl}│              │               │
    │─────────────►│              │               │
    │              │ Generate State               │
    │              │ Store State Data             │
    │              │──────────────────────────────►
    │              │                              │
    │◄─────────────│                              │
    │ {authUrl,    │                              │
    │  state}      │                              │
    │              │                              │
    │══════════════════════════════════════════════
    │ Redirect to SSO Provider                    │
    │═══════════════►│                            │
    │                │ User Authenticates         │
    │                │◄────────────►              │
    │◄═══════════════│                            │
    │ Redirect with code, state                   │
    │══════════════════════════════════════════════
    │              │              │               │
    │ GET /sso/callback          │               │
    │ {code, state}│              │               │
    │─────────────►│              │               │
    │              │ Validate State               │
    │              │──────────────────────────────►
    │              │◄─────────────────────────────│
    │              │              │               │
    │              │ Exchange Code                │
    │              │─────────────►│               │
    │              │◄─────────────│               │
    │              │ Get User Info                │
    │              │─────────────►│               │
    │              │◄─────────────│               │
    │              │              │               │
    │              │ Find/Create User             │
    │              │ Link Provider                │
    │              │──────────────────────────────►
    │              │                              │
    │              │ Generate Tokens              │
    │              │──────────────────────────────►
    │              │                              │
    │◄─────────────│                              │
    │ {user, tokens}                              │
```

## Getting Started

### Prerequisites

- Go 1.21+
- PostgreSQL 13+
- (Optional) Redis for distributed rate limiting

### Installation

```bash
# Clone the repository
git clone https://github.com/rw3iss/auth.git
cd auth

# Install dependencies
go mod tidy

# Set up environment variables (see Configuration section)
cp .env.example .env
# Edit .env with your settings

# Run database migrations
psql -U postgres -d auth -f migrations/001_initial_schema.up.sql
psql -U postgres -d auth -f migrations/002_seed_data.up.sql

# Run the server
go run cmd/server/main.go

# (Optional) Seed an initial system-admin user
go run cmd/seed/main.go
```

### Docker (Quick Start)

```bash
# Start all services (PostgreSQL, Redis, Auth Server)
make docker-up

# Verify it's running
curl http://localhost:8080/health
```

See the [Docker Setup](#docker-setup) section for more details.

## Docker Setup

### Quick Start

```bash
# Build and start all services
make docker-up
```

This starts three services:

| Service | URL | Description |
|---------|-----|-------------|
| Auth Server | http://localhost:8080 | rw3iss Auth API |
| PostgreSQL | localhost:5433 | Database (user: postgres, password: postgres) |
| Redis | localhost:6380 | Token cache and rate limiting |

### Commands

```bash
make docker-build   # Build the Docker image
make docker-up      # Start all services
make docker-down    # Stop all services
make docker-logs    # View live logs
make docker-clean   # Stop and remove all data (volumes)
```

### Environment

Docker uses `.env.docker` for configuration. PostgreSQL migrations are automatically applied on first start via Docker's `initdb.d` mechanism.

## Running Tests

### Unit Tests

```bash
make test
```

### Integration Tests

Integration tests run against real PostgreSQL and Redis instances via Docker:

```bash
make test-integration
```

This will:
1. Start PostgreSQL and Redis containers
2. Apply migrations
3. Run all integration tests (`tests/` directory)
4. Clean up containers

Test files use the `//go:build integration` build tag and cover:
- Registration (success, duplicate, validation)
- Login (success, wrong password, lockout, remember me)
- Token operations (refresh, revoke, validate)
- Password management (reset request, change)
- Session management (list, terminate, logout all)
- Rate limiting (under limit, exceeds limit)

## Configuration

Environment variables. **Required** vars are validated at boot — the server refuses to start without them, with weak placeholder secrets (`secret`, `changeme`, `test`, …), or with `CORS_ORIGINS=*` in production.

```bash
# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
ENVIRONMENT=development        # development | production
LOG_LEVEL=info                 # debug | info | warn | error

# Database (required)
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=auth
DB_SSL_MODE=disable
DB_MAX_OPEN_CONNS=25
DB_MAX_IDLE_CONNS=5

# JWT (required — ≥32 chars, must differ)
JWT_ACCESS_SECRET=
JWT_REFRESH_SECRET=
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h
JWT_REMEMBER_ME_EXPIRY=720h
JWT_ISSUER=ven-auth
JWT_AUDIENCE=ven-platform

# Server-side refresh idle policy (optional)
# When >0, /auth/refresh rejects + family-revokes any chain whose row was
# created more than this far in the past. The row's created_at equals the
# previous rotation, so this is "time since chain was last advanced" =
# inactivity of the whole chain. Pairs with the SDK's IdleTracker for
# defense-in-depth (client gates refresh, server enforces).
AUTH_REFRESH_IDLE_TIMEOUT=0

# JWT rotation (optional — set during a rotation window only)
# When set: validators try the active secret first, fall back to the previous
# secret on signature-mismatch only. Signing always uses the active secret.
# After max-token-lifetime (refresh 7d or 30d with remember_me) clear these
# to complete the rotation. See docs/Development.md §JWT secret rotation.
JWT_ACCESS_SECRET_PREVIOUS=
JWT_REFRESH_SECRET_PREVIOUS=

# Password policy
AUTH_PASSWORD_MIN_LENGTH=8
AUTH_PASSWORD_MAX_LENGTH=128
AUTH_PASSWORD_REQUIRE_UPPER=true
AUTH_PASSWORD_REQUIRE_LOWER=true
AUTH_PASSWORD_REQUIRE_DIGIT=true
AUTH_PASSWORD_REQUIRE_SPECIAL=false
BCRYPT_COST=12

# Auth flow
AUTH_MAX_LOGIN_ATTEMPTS=5
AUTH_LOCKOUT_DURATION=15m
AUTH_PASSWORD_RESET_EXPIRY=1h
AUTH_EMAIL_VERIFICATION_EXPIRY=24h
AUTH_INVITATION_EXPIRY=168h
AUTH_ACCOUNT_ATTEMPTS_LIMIT=20
AUTH_ACCOUNT_ATTEMPTS_WINDOW=1h
AUTH_ALLOW_BASE_USER_LOGIN=false  # if true, /auth/login may omit app_code
AUTH_DEFAULT_APP_CODE=            # fallback app_code

# Rate limit + trust
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=1m
TRUSTED_PROXIES=                  # comma-separated CIDRs

# CORS
CORS_ORIGINS=http://localhost:3001  # NEVER `*` in production

# SSO - Google
SSO_GOOGLE_ENABLED=true
SSO_GOOGLE_CLIENT_ID=
SSO_GOOGLE_CLIENT_SECRET=
SSO_ALLOWED_REDIRECT_URLS=https://app.ryanweiss.net/auth/callback,https://*.staging.ryanweiss.net/auth/callback*

# Audit log
AUDIT_ENABLED=true
AUDIT_BUFFER_SIZE=1024

# Cognito auto-migrate (optional)
COGNITO_AUTO_MIGRATE_ENABLED=false
COGNITO_REGION=
COGNITO_USER_POOL_ID=
COGNITO_CLIENT_ID=
COGNITO_CLIENT_SECRET=

# Email
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=noreply@example.com
SMTP_PASSWORD=password
EMAIL_FROM_ADDRESS=noreply@example.com
EMAIL_FROM_NAME=rw3iss Auth

# Redis (optional - graceful fallback if unavailable)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0
REDIS_POOL_SIZE=10
```

## API Documentation

### Authentication Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/auth/register` | Register a new user; `mode` field selects `register` / `register_or_login` / `register_or_return` | No |
| POST | `/api/v1/auth/login` | Login (requires `app_code` unless `AUTH_ALLOW_BASE_USER_LOGIN` is true; accepts optional `two_factor_code` for 2FA accounts) | No |
| POST | `/api/v1/auth/refresh` | Refresh tokens (family-aware rotation; reuse → family revoke) | No |
| POST | `/api/v1/auth/logout` | Revoke current refresh token | No |
| POST | `/api/v1/auth/logout/all` | Revoke all refresh tokens + bump per-user token-version | Yes |
| GET | `/api/v1/auth/me` | Current user + roles/permissions/org/app context | Yes |
| GET | `/api/v1/me/apps` | App memberships for current user | Yes |
| GET | `/api/v1/me/orgs` | Organization memberships for current user (self-service; mirror of `/me/apps`) | Yes |
| GET | `/api/v1/me/invitations` | Pending invitations addressed to the user's email | Yes |
| POST | `/api/v1/me/invitations/{id}/accept` | Accept an invitation; creates org membership + assigns roles | Yes |
| POST | `/api/v1/me/invitations/{id}/decline` | Decline an invitation | Yes |
| POST | `/api/v1/auth/password/reset-request` | Request password reset email | No |
| POST | `/api/v1/auth/password/reset` | Reset password (single-use token) | No |
| POST | `/api/v1/auth/password/change` | Change password | Yes |
| POST | `/api/v1/auth/2fa/setup` | Begin TOTP enrollment — returns provisioning URI + base32 secret | Yes |
| POST | `/api/v1/auth/2fa/enable` | Submit first TOTP code to complete enrollment | Yes |
| POST | `/api/v1/auth/2fa/disable` | Disable 2FA — requires password + current code | Yes |
| POST | `/api/v1/auth/verify-email` | Verify email (single-use token) | No |
| GET | `/api/v1/auth/sessions` | List active sessions | Yes |
| DELETE | `/api/v1/auth/sessions/{id}` | Terminate a session | Yes |

### SSO Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/auth/sso/url` | Get SSO authorization URL (redirect URL allowlisted). Optional PKCE: `code_challenge` + `code_challenge_method=S256`. | No |
| GET\|POST | `/api/v1/auth/sso/callback` | SSO callback (atomic state validation). Returns `{auth_code, expires_in}` instead of tokens when PKCE was initiated. | No |
| POST | `/api/v1/auth/sso/exchange` | Redeem a PKCE `auth_code` for a token pair using `code_verifier` | No |
| GET | `/api/v1/auth/sso/providers` | List enabled SSO providers | No |

### Token Validation (Internal)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/auth/validate` | Validate an access token (for services without the shared secret) | No |

### OAuth2 Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/oauth/token` | OAuth2 client_credentials grant (RFC 6749 §4.4). Body: `grant_type=client_credentials`, `client_id`, `client_secret`, optional `scope`. Accepts form-encoded or JSON. Issues a service-principal token (`token_type: "service"`). Failures collapse to `invalid_client` to prevent enumeration. | No (client_id + client_secret in body) |

### Identity Provider — OIDC (migration 025)

Other applications send a person here to sign in and receive a verifiable token, without ever handling their
credentials. Tokens are **RS256** with a `kid` header, verifiable against the published JWKS.

**Discovery lives at the ROOT, not under `API_PREFIX`** — the spec fixes these paths relative to the issuer,
and no client library looks anywhere else.

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/.well-known/openid-configuration` | OIDC Discovery 1.0 document | No |
| GET | `/.well-known/jwks.json` | Public signing keys (public by design) | No |
| GET | `/api/v1/oauth/authorize` | Authorization-code flow + PKCE (S256 only) and the consent screen | Optional (bounced to login) |
| POST | `/api/v1/oauth/token` | `authorization_code` grant → `id_token` + token pair (also serves `client_credentials`) | client_id + secret / PKCE |
| GET\|POST | `/api/v1/oauth/userinfo` | OIDC standard profile endpoint | Bearer |
| GET | `/api/v1/oauth/logout` | RP-initiated logout (registered post-logout URIs only) | No |
| GET\|POST\|PATCH\|DELETE | `/api/v1/admin/oauth/clients…` | Relying-party registry: create, list, update, rotate secret, delete | Platform admin |

### Identity Provider — FedCM

Browser-mediated "Sign in with CivicGate" — the browser draws the account chooser, so no popup and no
third-party cookies. **Reuses the OIDC keys, client registry and consent table**; no migration, no second
identity system. Full guide: [`docs/FEDCM.md`](./docs/FEDCM.md).

Root-level paths, for the same reason OIDC discovery is. **Every one requires `Sec-Fetch-Dest: webidentity`**
(except `/fedcm/login`) — a forbidden header name only the browser can set, which is what stops these being
credentialed identity reads callable by any page. `curl` must send it too.

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/.well-known/web-identity` | Names the config URL. ⚠ **The browser fetches this from the eTLD+1** (`civicgate.org`), not from `auth.civicgate.org` — see `docs/FEDCM.md` §3 | No |
| GET | `/fedcm/config.json` | Provider manifest: endpoints, `login_url`, branding | No |
| GET | `/fedcm/accounts` | The signed-in accounts. `401` = signed out | **Session cookie** |
| POST | `/fedcm/assertion` | Mints the ID token for one relying party. Validates `client_id`, `Origin`, `account_id`, `nonce`. Credentialed CORS | **Session cookie** |
| GET | `/fedcm/client-metadata` | The relying party's privacy / terms links | No (uncredentialed by design) |
| POST | `/fedcm/disconnect` | Drops the consent row for one relying party | **Session cookie** |
| GET | `/fedcm/login` | The `login_url` page — sets the browser's login-status bit | Optional |

FedCM needs the session as a **cookie**: the browser makes these calls itself and cannot attach an
`Authorization` header. `POST /api/v1/auth/login` therefore accepts **`cookie_mode: true`**, which additionally
writes `HttpOnly` session cookies (the token pair is still returned in the body). `AUTH_COOKIE_CROSS_SITE`
(default: on when the provider is enabled) makes them `SameSite=None; Secure` — **required**, because a `Lax`
cookie is not attached on the relying party's origin and the endpoint would honestly answer "no accounts".

`SameSite=None` gives up the browser's own login-CSRF defence, so cookies are written **only for a
first-party login** (`Sec-Fetch-Site`, with an `Origin` allow-list fallback). A cross-site login still
succeeds and still returns its tokens; it just gets no cookies. See `docs/FEDCM.md` §4.

### Service-Only Endpoints

Gated to `system_admin` token today; future M2M tokens once available.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/check-email` | `{exists: bool}` — never expose to public clients (user-enumeration leak) |
| POST | `/api/v1/auth/admin/set-password` | Set user password without current-password check |

### Org Self-Service Endpoints

`RequireOrgContext` + per-action permission. `system_admin` bypasses the path-match.

| Method | Endpoint | Permission |
|--------|----------|------------|
| GET | `/api/v1/orgs/{orgId}` | `org:read` |
| PUT | `/api/v1/orgs/{orgId}` | `org:update` |
| GET | `/api/v1/orgs/{orgId}/members` | `org:members:read` |
| POST | `/api/v1/orgs/{orgId}/members` | `org:members:invite` |
| DELETE | `/api/v1/orgs/{orgId}/members/{userId}` | `org:members:remove` |
| PUT | `/api/v1/orgs/{orgId}/members/{userId}/status` | `org:members:update` |
| GET | `/api/v1/orgs/{orgId}/roles` | `org:roles:read` |
| GET | `/api/v1/orgs/{orgId}/roles/{roleId}` | `org:roles:read` |
| POST | `/api/v1/orgs/{orgId}/roles` | `org:roles:create` (custom org role; permissions limited to org_assignable) |
| PUT | `/api/v1/orgs/{orgId}/roles/{roleId}` | `org:roles:update` |
| DELETE | `/api/v1/orgs/{orgId}/roles/{roleId}` | `org:roles:delete` |
| GET | `/api/v1/orgs/{orgId}/permissions/assignable` | `org:roles:read` (permission picker) |
| POST | `/api/v1/orgs/{orgId}/invitations` | `org:members:invite` (invite by email) |
| GET | `/api/v1/orgs/{orgId}/invitations` | `org:members:read` (list pending) |
| DELETE | `/api/v1/orgs/{orgId}/invitations/{id}` | `org:members:invite` (revoke) |

### Admin Endpoints

Two gates:
- **`/admin/*`** (data + ops) — `system_admin` OR `super_admin`.
- **`/admin/apps/*`**, **`/admin/permissions/register`**, **`/admin/m2m-clients/*`** (platform internals) — `system_admin` only.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET\|POST | `/admin/users[/...]` | User listing, role management, organization listing |
| POST | `/admin/users/lookup` | Bulk-resolve users by `{ emails?, ids? }` — single round-trip, ≤200 keys, excludes soft-deleted |
| GET | `/admin/users/{userId}/sessions` | List a target user's active sessions (admin-side mirror of `/auth/sessions`) |
| DELETE | `/admin/users/{userId}/sessions/{sessionId}` | Terminate one specific session for a target user |
| POST | `/admin/users/{userId}/revoke-sessions` | Terminate every session for a target user (bulk logout-all-for-them) |
| GET\|POST\|PUT\|DELETE | `/admin/organizations[/...]` | Org + membership CRUD |
| GET\|POST | `/admin/jobs[/{name}/{trigger\|pause\|resume}]` | Background-job management |
| POST\|GET\|PATCH\|DELETE | `/admin/apps[/...]` | App registry CRUD (**system_admin only**). Apps carry outbound `webhooks` (migration 019) dispatched async on `user.registered` |
| GET | `/admin/users/{userId}/apps` | List a user's active app memberships (admin view of `/me/apps`) |
| POST\|DELETE | `/admin/users/{userId}/apps/{appId}` | Grant/revoke user_apps membership |
| GET | `/admin/namespaces` | Pool catalog — every user pool with user counts (home/tag/total) + referencing app codes (**system_admin only**) |
| GET | `/admin/users/{userId}/namespaces` | A user's home (default) pool + tag pools (**system_admin only**) |
| PUT | `/admin/users/{userId}/namespace` | Move a user's default pool — 409 if the email already exists in the target pool (**system_admin only**) |
| POST\|DELETE | `/admin/users/{userId}/namespaces[/{ns}]` | Tag / untag a user into additional pools; the home pool is refused (**system_admin only**) |
| POST | `/admin/permissions/register` | Service self-registers permission catalog (**system_admin only**) |
| POST\|GET\|DELETE | `/admin/m2m-clients[/{clientId}]` | OAuth2 client_credentials registry — create returns plaintext secret once; soft-revoke (**system_admin only**) |

See `docs/APP_REGISTRATION.md` for the new-app onboarding flow.

### Health Check

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health check |

## Database Schema

See `migrations/` directory for full schema. Key tables:

- `users` - User accounts
- `organizations` - Multi-tenant organizations
- `organization_members` - User-organization relationships
- `roles` - System and custom roles
- `permissions` - Available permissions
- `role_permissions` - Role-permission mappings
- `user_base_roles` - User base role assignments
- `organization_member_roles` - Org member role assignments
- `invitations` - Organization invitations
- `refresh_tokens` - Stored refresh tokens
- `sessions` - Active user sessions
- `m2m_clients` - OAuth2 client_credentials registry (bcrypt-hashed secrets, soft-revoke, scopes TEXT[])

## Security

### Password Requirements
- Minimum 8 characters
- Must contain uppercase and lowercase letters
- Must contain at least one number
- Hashed using bcrypt

### Token Security
- Access tokens: Short-lived (15 min default)
- Refresh tokens: Longer-lived, stored in database
- Tokens can be revoked individually or all at once
- Session tracking with device info

### Rate Limiting
- Configurable requests per time window
- Per-client IP tracking
- Automatic cleanup of expired entries

### Account Protection
- Automatic lockout after failed attempts
- Configurable lockout duration
- Login attempt tracking

## Project Structure

```
auth/
├── cmd/
│   └── server/
│       └── main.go              # Application entry point
├── internal/
│   ├── api/
│   │   ├── dto/                 # Data Transfer Objects
│   │   ├── handlers/            # HTTP handlers
│   │   ├── middleware/          # HTTP middleware (rate limiting, auth, CORS)
│   │   └── routes/              # Route configuration
│   ├── auth/
│   │   ├── jwt/                 # JWT token management (with cache integration)
│   │   └── sso/                 # SSO provider implementations
│   ├── cache/                   # Redis cache layer
│   │   ├── redis.go             # Redis client with graceful fallback
│   │   └── token_cache.go       # TokenCache interface + Redis/NoOp implementations
│   ├── config/                  # Configuration management
│   ├── domain/                  # Domain models
│   ├── email/                   # Email service
│   ├── repository/              # Data access layer
│   │   └── postgres/            # PostgreSQL implementations
│   └── service/                 # Business logic layer
├── pkg/
│   └── shared/                  # Shared packages (for reuse)
│       ├── errors/              # Error types
│       ├── models/              # Shared models
│       ├── types/               # Common types
│       └── utils/               # Utility functions
├── tests/                       # Integration tests
│   ├── helpers/                 # Test environment, client, fixtures
│   ├── auth_register_test.go
│   ├── auth_login_test.go
│   ├── auth_token_test.go
│   ├── auth_password_test.go
│   ├── auth_session_test.go
│   └── auth_ratelimit_test.go
├── scripts/
│   ├── entrypoint.sh            # Docker entrypoint (health checks, migrations)
│   └── run-tests.sh             # Integration test runner
├── migrations/                  # Database migrations
├── Dockerfile                   # Multi-stage build
├── docker-compose.yml           # Local dev stack (postgres + redis + server)
├── Makefile                     # Build, test, and Docker commands
└── .env.docker                  # Docker environment configuration
```

## Deployment

### Production: ven-internal (current)

Live at **`https://auth.ryanweiss.net/`** (health: `https://auth.ryanweiss.net/health`).

Runs as a native Go binary under systemd on the ven-internal EC2 box (3.12.0.133). Nginx (Docker, `ven-nginx` on `/opt/ven-cms/`) terminates SSL on 443 and reverse-proxies to `127.0.0.1:8090`. The auth-server shares the box's `ven-postgres` container (DB `auth`) and `ven-redis` container (DB index 1).

| Piece                              | Path                                                  |
|------------------------------------|-------------------------------------------------------|
| Systemd unit                       | `/etc/systemd/system/auth-server.service` (see `deploy/systemd/auth-server.service`) |
| Binary                             | `/home/ec2-user/apps/auth-server/auth-server`         |
| Env file (chmod 600)               | `/home/ec2-user/apps/auth-server/.env`                |
| Migrations                         | `/home/ec2-user/apps/auth-server/migrations/`         |
| Nginx vhost                        | `/opt/ven-cms/nginx/conf.d/auth.ryanweiss.net.conf` (see `deploy/nginx/`) |
| SSL cert                           | `/etc/letsencrypt/live/auth.ryanweiss.net/` (auto-renewing) |

**Deploy flow:** push to `production` branch on `rw3iss/auth-server`. GitHub Actions (`.github/workflows/deploy.yml`) runs `go build ./...` + `go test ./internal/...`, then on success scps the Linux binary + migrations and `sudo systemctl restart auth-server`. A 5-attempt `/health` probe gates success.

Devs merge to `main`, then fast-forward `production` → `main` when ready:

```bash
git checkout production && git merge --ff-only main && git push origin production
```

A `pre-push` git hook (`scripts/git-hooks/pre-push`) runs the same build+test gate locally. Install once per clone:

```bash
make install-hooks
```

**Operator commands** (from the server):

```bash
sudo systemctl status auth-server         # status
sudo journalctl -u auth-server -f         # live logs
sudo systemctl restart auth-server        # manual restart (also done by CI)
curl https://auth.ryanweiss.net/health # public probe
```

The systemd unit is `Restart=always`, `RestartSec=5`, `StartLimitIntervalSec=0` — it retries forever on crash. Logs land in journald.

### AWS ECS Considerations (alternative path)

- **Container**: Use the multi-stage Dockerfile for minimal image size
- **Database**: Use Amazon RDS for PostgreSQL with SSL enabled (`DB_SSL_MODE=require`)
- **Cache**: Use Amazon ElastiCache for Redis (set `REDIS_HOST` to your cluster endpoint)
- **Secrets**: Use AWS Secrets Manager or Parameter Store for `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, and database credentials
- **Health Check**: Configure ECS health check against `GET /health`
- **Networking**: Place the auth server in a private subnet with ALB in public subnet

### Environment Variables for Production

```bash
ENVIRONMENT=production
DB_SSL_MODE=require
DB_MAX_OPEN_CONNS=50
REDIS_POOL_SIZE=20
RATE_LIMIT_REQUESTS=60
RATE_LIMIT_WINDOW=1m
BCRYPT_COST=14
```

## Further Documentation

Deeper-dive docs live in the [`docs/`](./docs/) directory:

- [`docs/How_It_Works.md`](./docs/How_It_Works.md) — End-to-end walkthrough of the auth lifecycle: registration, login, JWT issuance/refresh, RBAC checks, multi-tenant org isolation, and SSO flows.
- [`docs/Development.md`](./docs/Development.md) — Local development guide: project layout, running the server, seeding data, writing handlers/services, adding migrations, and the test workflow.
- [`docs/EMAIL_TEMPLATES.md`](./docs/EMAIL_TEMPLATES.md) — Themed HTML email system: the shared layout/shell + per-message templates, the light/dark shell variants, the recipient `default_color_mode` selection rule, `EMAIL_TEMPLATES_PATH` overrides, and how to add a new email type.
- [`docs/FEDCM.md`](./docs/FEDCM.md) — Browser-mediated sign-in: the seven FedCM endpoints, the `Sec-Fetch-Dest: webidentity` gate, why the well-known file must sit on the eTLD+1, why the session cookie must be `SameSite=None`, the login-status bit, and how a relying party registers.
- [`docs/IDENTITY-PROVIDER-AUDIT.md`](./docs/IDENTITY-PROVIDER-AUDIT.md) — The 2026-08 audit of this server as a third-party IdP, plus a status log of what has shipped since.

### Configurable API Prefix

All routes can be mounted under a configurable prefix via the `API_PREFIX` env var (default: empty). For example, setting `API_PREFIX=/api/v1` exposes endpoints as `/api/v1/auth/login`, `/api/v1/users`, etc. This makes it easy to put the auth server behind a shared API gateway without code changes.

## License

Copyright (c) 2024 rw3iss Platform. All rights reserved.
