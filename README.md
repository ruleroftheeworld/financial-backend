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
