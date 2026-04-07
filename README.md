# 🏦 Secure Financial Backend System

**FAANG-level Financial Data Processing & Access Control Backend**

Built on top of a production-grade IAM system — extended with a complete Finance Module, Dashboard Analytics, Swagger docs, Jest tests, and Kubernetes deployment.

---

## 📋 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Project Structure](#project-structure)
3. [Quick Start — Local](#quick-start--local)
4. [Docker Setup](#docker-setup)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [API Reference](#api-reference)
7. [Testing](#testing)
8. [Observability](#observability)
9. [Assumptions & Trade-offs](#assumptions--trade-offs)

---

## Architecture Overview

```
Client
  │
  ▼
Ingress (nginx / TLS termination)
  │
  ▼
Express.js API  (Node 20, ESM)
  ├── Helmet + HPP + CORS + Compression
  ├── Active Defense Middleware  (Redis-backed IP banning)
  ├── Redis Rate Limiter         (per-IP + per-email)
  ├── JWT authenticate()         (RS256, token-version check)
  ├── authorizeRoles()           (RBAC: USER / ADMIN / SECURITY_ANALYST)
  ├── authorizePolicy()          (ABAC: session-context + resource ownership)
  │
  ├── /api/v1/auth          →  Auth Module (register, login, MFA, refresh)
  ├── /api/v1/users         →  User Module (CRUD, role management)
  ├── /api/v1/analytics     →  Platform Analytics (ADMIN + ANALYST)
  ├── /api/v1/audit         →  Security Audit Logs
  │
  ├── /api/v1/finance/transactions   →  Transaction CRUD + soft-delete
  ├── /api/v1/finance/categories     →  Category management
  ├── /api/v1/finance/accounts       →  Account/Wallet management
  └── /api/v1/finance/dashboard      →  Analytics (summary, trends, breakdown)
  │
  ├── /docs        →  Swagger UI
  ├── /health      →  Liveness probe
  └── /metrics     →  Prometheus scrape endpoint
  │
  ▼                    ▼
PostgreSQL           Redis
(NUMERIC(20,2)       (rate-limit, sessions,
for amounts)          dashboard cache, event stream)
```

### Finance Module Design Decisions

| Concern | Decision | Reason |
|---|---|---|
| Monetary amounts | `NUMERIC(20,2)` in PostgreSQL, string in API | Prevents IEEE-754 float drift |
| Soft delete | `deletedAt` timestamp | Audit trail; ADMINs can restore |
| IDOR prevention | `userId` in every query + `ownershipGuard` middleware | Belt-and-suspenders |
| Caching | Redis with 5-min TTL per user + cache invalidation | Dashboard queries are read-heavy |
| Audit trail | Append-only `finance_audit_logs` with before/after JSON | Reconstructable history |

---

## Project Structure

```
api/
├── prisma/
│   ├── schema.prisma                          # DB schema (User, Session, Transaction, …)
│   ├── seed.js                                # Sample data (users + 90 days of transactions)
│   └── migrations/
│       └── 20260402000000_add_finance_module/ # Finance tables + default categories
│
├── src/
│   ├── app.js                                 # Express app (middleware stack + routes)
│   ├── server.js                              # Process bootstrap + graceful shutdown
│   │
│   ├── modules/
│   │   ├── auth/          (JWT, MFA, sessions, refresh tokens)
│   │   ├── user/          (CRUD, role management, internal API)
│   │   ├── analytics/     (Platform metrics — ADMIN/ANALYST only)
│   │   ├── audit/         (Security audit log reader)
│   │   └── finance/
│   │       ├── finance.audit.service.js       # Append-only finance audit log
│   │       ├── transaction/  (CRUD, soft-delete, restore)
│   │       ├── category/     (User + system categories)
│   │       ├── account/      (Wallet management)
│   │       └── dashboard/    (Summary, trends, breakdown — Redis cached)
│   │
│   ├── metrics/metrics.js                     # Prometheus counters + histograms
│   └── shared/
│       ├── config/
│       │   ├── index.js     (centralized config — secrets via file or env)
│       │   ├── database.js  (Prisma singleton)
│       │   ├── redis.js     (ioredis client)
│       │   └── swagger.js   (OpenAPI 3.0 spec)
│       ├── middleware/
│       │   ├── authenticate.js      (JWT + session + token-version check)
│       │   ├── authorizeRoles.js    (RBAC)
│       │   ├── authorizePolicy.js   (ABAC + session-hijack detection)
│       │   ├── ownershipGuard.js    (IDOR prevention)
│       │   ├── rateLimiter.js       (Redis-backed per-IP + per-email)
│       │   ├── validate.js          (express-validator result handler)
│       │   ├── errorHandler.js      (structured error responses)
│       │   └── activeDefender.js    (adaptive IP banning)
│       └── utils/
│           ├── AppError.js   jwt.js   password.js   cipher.js   response.js
│
├── tests/
│   ├── setup.js             # Jest global mocks (Prisma + Redis + logger)
│   ├── auth.test.js         # Registration, login, token validation
│   ├── finance.test.js      # Transaction/Category/Account/Dashboard CRUD
│   └── access-control.test.js  # RBAC, IDOR, mass-assignment, XSS
│
├── k8s/
│   ├── namespace.yaml   configmap.yaml   secret.yaml
│   ├── deployment.yaml  service.yaml     hpa.yaml    ingress.yaml
│
├── postman/
│   └── financial-backend.postman_collection.json
│
├── grafana/
│   └── financial-backend-dashboard.json
│
├── package.json    Dockerfile    docker-compose.yml    .env.example
```

---

## Quick Start — Local

### Prerequisites
- Node.js 20+
- PostgreSQL 16
- Redis 7

### 1. Install & configure

```bash
# Clone / extract the project
cd api

# Install dependencies
npm install

# Copy and fill in environment variables
cp .env.example .env
# Edit .env — at minimum set DATABASE_URL, REDIS_URL, JWT keys

# Generate RS256 JWT keys
node scripts/generate-keys.js
```

### 2. Database

```bash
# Run all migrations (creates finance tables + default categories)
npm run migrate

# Seed sample data (users + 90 days of transactions for user@example.com)
npm run seed
```

### 3. Start the server

```bash
npm run dev        # nodemon (auto-reload)
# or
npm start          # production mode
```

Server: `http://localhost:3000`
Swagger UI: `http://localhost:3000/docs`
Metrics: `http://localhost:3000/metrics`

### Seeded credentials

| Role | Email | Password (from .env) |
|---|---|---|
| ADMIN | admin@example.com | `SEED_ADMIN_PASSWORD` |
| SECURITY_ANALYST | analyst@example.com | `SEED_ANALYST_PASSWORD` |
| USER | user@example.com | `SEED_USER_PASSWORD` |

---

## Docker Setup

```bash
# Build and start all services (API + Postgres + Redis + Prometheus + Grafana)
docker compose up --build

# Run migrations + seed in the running stack
docker compose run --rm seed

# View logs
docker compose logs -f backend

# Stop everything
docker compose down -v
```

**Services:**
| Service | Port |
|---|---|
| API | `localhost:3000` |
| Swagger | `localhost:3000/docs` |
| Prometheus | `localhost:9090` |
| Grafana | `localhost:3001` (admin/admin) |

---

## Kubernetes Deployment

### Prerequisites
- `kubectl` configured
- Container registry accessible
- cert-manager + nginx-ingress installed (for TLS/Ingress)

### 1. Build & push image

```bash
docker build -t your-registry/financial-backend:v2.0.0 .
docker push your-registry/financial-backend:v2.0.0
```

### 2. Prepare secrets

```bash
# Encode each secret value
echo -n "postgresql://..." | base64

# Edit k8s/secret.yaml with encoded values
# (In production: use Sealed Secrets or External Secrets Operator)
```

### 3. Deploy

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Apply ConfigMap, Secrets
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml

# Deploy application
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/ingress.yaml

# Verify
kubectl -n financial-backend get pods
kubectl -n financial-backend get hpa
```

### 4. Access

```bash
# Port-forward for local testing
kubectl -n financial-backend port-forward svc/financial-backend 3000:80

# Or via Ingress (update k8s/ingress.yaml with your domain)
curl https://api.example.com/health
```

---

## API Reference

All finance endpoints require `Authorization: Bearer <accessToken>`.

### Authentication
| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login → returns accessToken |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Revoke session |

### Transactions
| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/finance/transactions` | Create transaction |
| GET | `/api/v1/finance/transactions` | List (paginated, filtered) |
| GET | `/api/v1/finance/transactions/:id` | Get by ID |
| PATCH | `/api/v1/finance/transactions/:id` | Update |
| DELETE | `/api/v1/finance/transactions/:id` | Soft delete |
| POST | `/api/v1/finance/transactions/:id/restore` | Restore (ADMIN) |

**Query filters:** `type`, `categoryId`, `accountId`, `startDate`, `endDate`, `sortBy`, `sortOrder`, `page`, `limit`

**Amount format:** Always a **string** (e.g. `"1500.00"`) — never a float.

### Dashboard
| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/finance/dashboard/summary` | Total income, expense, net balance |
| GET | `/api/v1/finance/dashboard/category-breakdown` | Grouped by category |
| GET | `/api/v1/finance/dashboard/monthly-trends` | Last N months |
| GET | `/api/v1/finance/dashboard/recent` | Most recent transactions |

Full interactive docs: `http://localhost:3000/docs`

---

## Testing

```bash
# Run all tests
npm test

# With coverage report
npm run test:coverage

# Watch mode (TDD)
npm run test:watch
```

Test suites:
- `auth.test.js` — registration, login, JWT validation, 404 handler
- `finance.test.js` — CRUD validation, 201/404/422 status codes, pagination envelope
- `access-control.test.js` — RBAC enforcement, IDOR prevention, mass-assignment, XSS

---

## Observability

### Prometheus metrics (auto-scraped at `/metrics`):

| Metric | Description |
|---|---|
| `finance_transactions_total` | Transactions by action + type |
| `finance_api_duration_seconds` | Histogram of finance endpoint latency |
| `finance_dashboard_cache_hits_total` | Cache hit/miss ratio |
| `iam_requests_total` | All HTTP requests by method/route/status |
| `iam_login_duration_seconds` | Login latency histogram |
| `iam_auth_failures_total` | Auth middleware failures |
| `iam_ip_bans_total` | Active Defense bans |
| `iam_authorization_failures_total` | RBAC/ABAC denials |

### Grafana dashboard
Import `grafana/financial-backend-dashboard.json` into Grafana (Prometheus datasource required).

---

## Assumptions & Trade-offs

### Assumptions
1. Single-currency per transaction (multi-currency conversion is out of scope).
2. Account balance is informational — not auto-debited/credited on transaction creation. A future double-entry accounting module would handle this.
3. JWT RS256 keys are pre-generated via `scripts/generate-keys.js` before deployment.
4. ADMIN users operate from within the private network (Docker/K8s RFC 1918) — enforced by the existing IP-bound ABAC policy.

### Trade-offs

| Decision | Trade-off |
|---|---|
| **PostgreSQL** for all data | Strong ACID, NUMERIC type for money. Trade-off: harder to scale writes horizontally vs. NoSQL. |
| **Soft delete** on transactions | Enables audit/restore. Trade-off: queries must always filter `deletedAt IS NULL`; handled in every service method. |
| **Redis cache for dashboard** | Fast repeated reads. Trade-off: 5-min eventual consistency. Stale on rapid transactions. |
| **String amounts in API** | No float drift risk. Trade-off: clients must parse the string before display arithmetic. |
| **Mocked tests (no testcontainers)** | Fast CI (< 5s). Trade-off: doesn't catch real DB constraint violations. Add testcontainers for true integration coverage. |
| **Monorepo structure** | Simple deployment. Trade-off: a microservices split (auth-service / finance-service) would give independent scaling but adds network overhead. |

---

## 🔐 Security Testing Report

> Conducted via manual Postman testing + Jest suite (48 tests).
> All findings below are from live API testing against the local dev environment.
> Phases 1–5 completed. Phases 6–8 (Business Logic, Soft Delete, MFA) pending.

---

### Testing Phases Overview

| Phase | Area | Tests Run | Bugs Found | Status |
|-------|------|-----------|------------|--------|
| Phase 1 | Input Validation | 14 | 6 | ✅ Complete |
| Phase 2 | RBAC Expansion | 10 | 1 | ✅ Complete |
| Phase 3 | Race Conditions | 5 | 1 | ✅ Complete |
| Phase 4 | Token Management | 6 | 0 | ✅ Complete |
| Phase 5 | Rate Limiting & Brute Force | 5 | 4 | ✅ Complete |
| Phase 6 | Business Logic / Insufficient Funds | — | — | 🔲 Pending |
| Phase 7 | Soft Delete Edge Cases | — | — | 🔲 Pending |
| Phase 8 | MFA / TOTP Completion | — | — | 🔲 Pending |

---

### Bug Registry

#### 🔴 Critical

---

**BUG-RC-001 — Concurrent Refresh Token Reuse (TOCTOU Race Condition)**
- **Phase:** Race Conditions
- **Endpoint:** `POST /api/v1/auth/refresh`
- **Description:** When the same refresh token is used in 5 simultaneous requests (0ms delay), all 5 succeed and return unique valid access tokens. Sequential reuse detection works correctly but fails under concurrency due to a Time-of-Check to Time-of-Use (TOCTOU) race.
- **Impact:** An attacker with one stolen refresh token can spawn unlimited parallel sessions. All issued access tokens remain valid until expiry.
- **Reproduce:** Login → send 5 concurrent POST /auth/refresh with same refresh token cookie → all return 200 OK with unique tokens.
- **Fix:** Wrap the token check and mark-as-used in an atomic DB transaction using `SELECT FOR UPDATE` or a compare-and-swap (CAS) on the token `used` flag.

---

**BUG-RL-001 — Correct Password Bypasses Active Account Lockout**
- **Phase:** Rate Limiting & Brute Force
- **Endpoint:** `POST /api/v1/auth/login`
- **Description:** After 5 failed login attempts the account is locked (`lockUntil` set). However, submitting the correct password during the lockout window returns `200 OK` and issues a valid access token — completely bypassing the lockout.
- **Impact:** Brute force protection is defeated. An attacker can try 4 wrong passwords then the correct one, cycling indefinitely without ever being truly locked out.
- **Reproduce:** Fail login 5 times → account locked → login with correct password → 200 OK.
- **Fix:** In `auth.service.js`, check `lockUntil > now` **before** password verification, not after. Lockout must be enforced regardless of password correctness.

---

#### 🔴 High

---

**BUG-001 — `account_id` Never Validated — Transactions Always Created with `accountId: null`**
- **Phase:** Input Validation
- **Endpoint:** `POST /api/v1/finance/transactions`
- **Description:** The `account_id` field sent in the request body is silently ignored. Every transaction is created with `accountId: null` regardless of what value is supplied. The field is not listed as required in validation errors.
- **Impact:** Transactions are never linked to accounts. Balance tracking is broken. Orphaned records accumulate in the DB. Also masks race condition testing on balance deductions.
- **Reproduce:** POST /transactions with any valid `account_id` → response always shows `accountId: null`.
- **Fix:** Add `account_id` as a required, validated UUID field in the transaction validator. Verify account ownership before insert. Use `accountId` (camelCase) consistently — Jest tests use `accountId` which may work differently from the `account_id` (snake_case) the API reads.

---

**BUG-005 — Mass Assignment: `currency` Field Overridable by User**
- **Phase:** Input Validation
- **Endpoint:** `POST /api/v1/finance/transactions`
- **Description:** Sending `currency` in the request body overrides the transaction currency. The field is not stripped before DB insertion.
- **Impact:** Users can assign arbitrary currencies (GBP, BTC, XYZ) to transactions on USD accounts, breaking all balance calculations and multi-currency reporting.
- **Reproduce:** POST /transactions with extra field `"currency": "GBP"` → response shows `currency: "GBP"` stored.
- **Fix:** Strip `currency` from the request body entirely. Derive it from the linked account at the service layer.

---

**BUG-RBAC-001 — Analyst Role Can Create Transactions (No Role Restriction on POST /transactions)**
- **Phase:** RBAC Expansion
- **Endpoint:** `POST /api/v1/finance/transactions`
- **Description:** The `SECURITY_ANALYST` role has no restriction on calling `POST /transactions`. The transaction was created successfully (201) with the Analyst's token. The Analyst role should be read-only for finance endpoints.
- **Impact:** Any authenticated user regardless of role can create financial transactions. Combined with BUG-001 (accountId null), fixing accountId could expose a full account hijack vector.
- **Reproduce:** Login as analyst → POST /transactions with valid body → 201 Created.
- **Fix:** Add `authorizeRoles('USER', 'ADMIN')` middleware to `POST /finance/transactions`. Analyst should only have GET access to finance endpoints.

---

#### 🟡 Medium

---

**BUG-002 — Non-ISO 8601 Date Silently Coerced Instead of Rejected**
- **Phase:** Input Validation
- **Endpoint:** `POST /api/v1/finance/transactions`
- **Description:** When sending `date` as `"04-04-2026"` (DD-MM-YYYY format), the API accepts and silently converts it to a valid ISO timestamp instead of rejecting it.
- **Impact:** Ambiguous date formats (DD-MM vs MM-DD) could result in transactions stored with wrong dates. Locale-sensitive bugs in reporting.
- **Fix:** Tighten the date validator to reject anything that isn't strictly ISO 8601 (`YYYY-MM-DDTHH:mm:ss.sssZ`). Do not rely on JS `Date` parsing which is too lenient.

---

**BUG-003 — Future Dates Accepted Without Restriction**
- **Phase:** Input Validation
- **Endpoint:** `POST /api/v1/finance/transactions`
- **Description:** Transactions dated as far as year 2099 are accepted with no validation or warning.
- **Impact:** Future-dated transactions affect current balance reporting, appear in dashboards, and mislead users or auditors.
- **Fix:** Add a validator rule: `date` must not be greater than `now + N days` (e.g. 7 days for scheduled transactions, or strictly `<= now` if scheduling is not a feature).

---

**BUG-004 — No Maximum Amount Validation**
- **Phase:** Input Validation
- **Endpoint:** `POST /api/v1/finance/transactions`
- **Description:** The API accepted a transaction amount of `"999999999999999.99"` without any upper bound check. The DB column is `NUMERIC(20,2)` which can technically hold it, but no business-level cap exists.
- **Impact:** No upper bound means potential precision edge cases and no protection against obviously erroneous entries.
- **Fix:** Add a max value validator — e.g. `amount must be <= "9999999999.99"` (10 billion) as a reasonable financial cap.

---

**BUG-006 — HTML Encoding Applied to REST API Text Fields**
- **Phase:** Input Validation
- **Endpoint:** `POST /api/v1/finance/transactions`
- **Description:** Description field content is HTML-encoded before storage (apostrophe stored as `&#x27;`, `<script>` stored as `&lt;script&gt;`). This is incorrect behavior for a JSON REST API — HTML escaping belongs in the frontend, not the backend.
- **Impact:** Data in DB is polluted with HTML entities. API consumers (mobile apps, reports) must decode HTML to display raw text correctly. Double-encoding risk if the frontend also escapes.
- **Fix:** Remove HTML encoding (`express-validator`'s `.escape()`) from transaction/description validators. Store raw strings. Let the frontend handle display escaping.

---

**BUG-RL-002 — Wrong HTTP Status Code for Account Lockout (403 instead of 423)**
- **Phase:** Rate Limiting
- **Endpoint:** `POST /api/v1/auth/login`
- **Description:** Account lockout returns `403 Forbidden` instead of the semantically correct `423 Locked`.
- **Fix:** Return `res.status(423)` for `ACCOUNT_LOCKED` errors in the login controller.

---

**BUG-RL-003 — Sensitive Internal Fields Leaked in Login Response**
- **Phase:** Rate Limiting
- **Endpoint:** `POST /api/v1/auth/login`
- **Description:** The login success response includes internal user fields: `failedLoginAttempts`, `lockUntil`, `tokenVersion`, `lastTempTokenJti`, `totpSecretKeyVersion`, `lastTempTokenUsedAt`.
- **Impact:** Exposes internal security state to clients. `failedLoginAttempts` tells an attacker exactly how many attempts remain before lockout.
- **Fix:** Whitelist the user fields returned in the login response. Only expose: `id`, `email`, `name`, `role`, `provider`, `totpEnabled`, `createdAt`.

---

#### ⚪ Low / Info

---

**BUG-RL-004 — No `retryAfter` Field in Lockout Response**
- **Phase:** Rate Limiting
- **Description:** When an account is locked, the error response does not include when the user can retry (`retryAfter` seconds or `lockUntil` timestamp).
- **Fix:** Include `"retryAfter": <seconds>` or `"lockUntil": "<ISO timestamp>"` in the `details` field of the `ACCOUNT_LOCKED` error response.

---

### What Passed ✅

| Area | Controls Verified |
|------|------------------|
| JWT Security | RS256 signing, `alg:none` blocked, signature validation, expiry enforcement |
| Session Management | Server-side revocation on logout, HTTP-only refresh cookie cleared |
| Token Tampering | Payload modification detected via signature mismatch |
| Malformed Tokens | Graceful rejection, no 500 crashes |
| IDOR | User A cannot read/delete User B's transactions or accounts (404) |
| Admin Routes | 403/404 for non-admin roles on `/api/v1/admin/*` and `/api/v1/users` |
| Idempotency | Concurrent requests with same Idempotency-Key return same TX ID |
| Concurrent Logins | 10 simultaneous logins produce unique tokens, no session collisions |
| Concurrent Account Creation | Clean unique records, no crashes or corruption |
| Input Validation | Negative/zero amounts, invalid types, 3+ decimals, garbage dates, oversized descriptions all correctly rejected |
| SQL Injection | ORM (Prisma) prevents SQL injection in all tested fields |
| Account Lockout (trigger) | Locks after exactly 5 failed attempts |

---

### Remediation Priority

```
IMMEDIATE (before any production deployment)
├── BUG-RL-001  Lockout bypass with correct password
├── BUG-RC-001  TOCTOU refresh token race condition
└── BUG-001     account_id never linked (breaks all balance logic)

HIGH (before beta/staging release)
├── BUG-005     currency mass assignment
├── BUG-RBAC-001 Analyst can create transactions
└── Re-run RC-001 balance race test after BUG-001 is fixed

MEDIUM (next sprint)
├── BUG-002     Non-ISO date coercion
├── BUG-003     Future date accepted
├── BUG-004     No max amount cap
├── BUG-006     HTML encoding in REST API
└── BUG-RL-003  Sensitive fields in login response

LOW (polish)
├── BUG-RL-002  403 → 423 for lockout
└── BUG-RL-004  Add retryAfter to lockout response
```

---

### Pending Test Areas

- **Phase 6 — Business Logic:** Insufficient funds (EXPENSE > balance), account type rules
- **Phase 7 — Soft Delete Edge Cases:** Transactions on deleted accounts, restore flows
- **Phase 8 — MFA Completion:** TOTP verify (blocked by clock sync issue — needs resolution)
- **Regression Testing:** Re-run all failed tests after fixes applied
- **Load Testing:** Artillery/k6 for true concurrency stress test beyond Postman Runner

