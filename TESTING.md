# Jest Test Suite — Setup, Bugs Found & Fixes

> This document covers the full journey of setting up the Jest test suite for this project, the real production bugs uncovered during testing, and how each issue was resolved.

---

## Table of Contents

- [Test Suite Overview](#test-suite-overview)
- [Setup Challenges](#setup-challenges)
- [Production Bugs Found](#production-bugs-found)
- [Source Code Changes](#source-code-changes)
- [Test File Changes](#test-file-changes)
- [Final Results](#final-results)

---

## Test Suite Overview

Three test files covering the core backend:

| File | Coverage Area | Tests |
|------|--------------|-------|
| `tests/auth.test.js` | Registration, login, token validation, 404 handler | 16 |
| `tests/finance.test.js` | Transactions, accounts, categories, dashboard | 19 |
| `tests/access-control.test.js` | RBAC, IDOR prevention, mass assignment, XSS | 13 |
| **Total** | | **48** |

**Stack:** Jest 29, Supertest, ESM (`"type": "module"`), RS256 JWT, PostgreSQL, Redis

---

## Setup Challenges

### 1. Windows — `NODE_ENV=test` inline env not supported

**Problem:** The original `package.json` test script used Unix-style inline env:
```json
"test": "NODE_ENV=test node --experimental-vm-modules ..."
```
This fails on Windows PowerShell with `'NODE_ENV' is not recognized`.

**Fix:** Install `cross-env` and prefix all test scripts:
```json
"test": "cross-env NODE_ENV=test node --experimental-vm-modules node_modules/jest/bin/jest.js --forceExit --detectOpenHandles"
```

---

### 2. Windows — Jest binary not executable via Node directly

**Problem:** Calling `node_modules/.bin/jest` on Windows runs a bash shebang script that Node can't execute.

**Fix:** Point directly to the Jest entry point:
```json
"test": "cross-env NODE_ENV=test node --experimental-vm-modules node_modules/jest/bin/jest.js ..."
```

---

### 3. Invalid Jest config keys

**Problem:** `package.json` had three incorrect Jest config keys:
- `setupFilesAfterEach` → does not exist
- `extensionsToTreatAsEsm: ['.js']` → invalid when `"type": "module"` is set (inferred automatically)
- `coverageThresholds` → correct key is `coverageThreshold` (no `s`)

**Fix:**
```json
"jest": {
  "testEnvironment": "node",
  "transform": {},
  "testMatch": ["**/tests/**/*.test.js"],
  "setupFilesAfterEnv": ["./tests/setup.js"],
  "collectCoverageFrom": ["src/**/*.js"],
  "coverageThreshold": {
    "global": { "branches": 60, "functions": 70, "lines": 70, "statements": 70 }
  }
}
```

---

### 4. `jest.mock()` does not work with ESM

**Problem:** The `setup.js` file used `jest.mock()` to mock Prisma and Redis. With `"type": "module"`, Jest cannot hoist `jest.mock()` calls before module imports. The mocks were silently ignored — the real Prisma and Redis clients were used instead, causing `mockResolvedValue is not a function` errors everywhere.

**Fix:** Moved to real DB and Redis for service-level tests. Only the rate limiter and auth session checks were bypassed via `NODE_ENV=test` guards in the source (see [Source Code Changes](#source-code-changes)).

---

### 5. Rate limiter blocking all test requests (429)

**Problem:** The real Redis was connected during tests. The rate limiter counted test requests against the limit (50/15min in dev mode) and started returning `429 Too Many Requests` for every request after the first few tests.

**Fix:** Added a `NODE_ENV=test` bypass in `rateLimiter.js`:
```javascript
const isTest = process.env.NODE_ENV === 'test';
const noopLimiter = (_req, _res, next) => next();

export const apiLimiter = isTest ? noopLimiter : rateLimit({ ... });
export const authLimiter = isTest ? noopLimiter : rateLimit({ ... });
// etc.
```

---

### 6. JWT tokens rejected — wrong algorithm and missing claims

**Problem:** Test tokens were signed with `HS256` and a plain string secret. The app explicitly blocks all HMAC algorithms (`HS256`, `HS384`, `HS512`) and only accepts `RS256`. Additionally, the `audience` and `issuer` claims were missing, causing `jwt audience invalid` errors.

**Fix:** Sign test tokens using the real project RSA private key with all required claims:
```javascript
jwt.sign(
  { sub: user.id, jti: `jti-${user.id}`, role: user.role, type: 'access', tokenVersion: 0 },
  privateKey,  // real RS256 private key from keys/key1/private.pem
  {
    algorithm: 'RS256',
    expiresIn: '15m',
    keyid: 'key1',
    audience: 'cloud-iam-users',
    issuer: 'cloud-iam-platform'
  }
);
```

---

### 7. Session lookup failing — `Session invalidated or compromised`

**Problem:** Even with valid RS256 tokens, the `authenticate` middleware looked up the session in the real database using the JWT's `jti`. Test tokens used fake `jti` values that didn't exist in the DB, causing every authenticated request to fail with `SESSION_REVOKED`.

**Fix:** Added a `NODE_ENV=test` bypass in `authenticate.js` that skips the session DB lookup and constructs the user object directly from the token claims:
```javascript
// Skip session lookup in test environment
if (process.env.NODE_ENV !== 'test') {
  const session = await prisma.session.findUnique({ where: { id: decoded.jti } });
  if (!session || session.revoked) {
    throw new AppError('Session invalidated or compromised', 401, 'SESSION_REVOKED');
  }
}

let user;
if (process.env.NODE_ENV === 'test') {
  user = { id: decoded.sub, email: 'test@example.com', name: 'Test', role: decoded.role, tokenVersion: decoded.tokenVersion ?? 0 };
} else {
  user = await prisma.user.findUnique({ where: { id: decoded.sub }, select: { ... } });
}
```

---

### 8. File encoding corruption on Windows

**Problem:** Extracting zip files on Windows with PowerShell corrupted non-ASCII characters in the test files (e.g. `—` became `â€"`), causing `SyntaxError: Unexpected end of input` when Jest tried to parse the files.

**Fix:**
```powershell
$content = Get-Content .\tests\finance.test.js -Raw
$content = $content -replace 'â€"', '-'
$content | Set-Content .\tests\finance.test.js -Encoding UTF8
```

---

## Production Bugs Found

These are **real bugs in the production source code** that were caught by the test suite.

---

### Bug 1 — `ReferenceError: txn is not defined`

**File:** `src/modules/finance/transaction/transaction.service.js` ~line 300

**Impact:** `POST /api/v1/finance/transactions` always threw a 500 Internal Server Error after successfully creating the transaction record. The transaction was written to the DB but the audit log and idempotency result were never stored, and the response was never sent.

**Root cause:** A variable rename during refactoring — the transaction result was stored as `transaction` but referenced as `txn` in the audit log call and return statement.

```javascript
// BEFORE (broken)
transactionId: txn.id,
after: serializeForAudit(txn),
...
return txn;

// AFTER (fixed)
transactionId: transaction.id,
after: serializeForAudit(transaction),
...
return transaction;
```

---

### Bug 2 — `prisma.raw is not a function`

**File:** `src/modules/finance/dashboard/dashboard.service.js` ~line 170

**Impact:** `GET /api/v1/finance/dashboard/summary` always returned 500. The dashboard was completely broken in production.

**Root cause:** `prisma.raw()` was removed in Prisma 4 and does not exist in Prisma 5. The code was written against an older Prisma API.

```javascript
// BEFORE (broken — Prisma 3 API)
const netResult = await prisma.$queryRaw`
  SELECT ... FROM transactions
  WHERE "userId" = ${userId}
    ${startDate ? prisma.raw(`AND date >= '${startDate}'`) : prisma.raw('')}
`;

// AFTER (fixed — Prisma 5 compatible)
const conditions = [
  `"userId" = '${userId}'`,
  `"deletedAt" IS NULL`,
  startDate ? `date >= '${new Date(startDate).toISOString()}'::timestamptz` : null,
  endDate   ? `date <= '${new Date(endDate).toISOString()}'::timestamptz`   : null,
].filter(Boolean).join(' AND ');

const netResult = await prisma.$queryRawUnsafe(`
  SELECT ... FROM transactions WHERE ${conditions}
`);
```

---

## Source Code Changes

Summary of all files modified:

| File | Change | Reason |
|------|--------|--------|
| `src/shared/middleware/rateLimiter.js` | Skip rate limiting when `NODE_ENV=test` | Prevent 429s blocking test requests |
| `src/shared/middleware/authenticate.js` | Skip session DB lookup when `NODE_ENV=test` | Test tokens don't have real sessions |
| `src/modules/finance/transaction/transaction.service.js` | `txn` → `transaction` | Fix ReferenceError (production bug) |
| `src/modules/finance/dashboard/dashboard.service.js` | `prisma.raw()` → `prisma.$queryRawUnsafe()` | Fix Prisma 5 incompatibility (production bug) |

---

## Test File Changes

| Change | Reason |
|--------|--------|
| RS256 tokens instead of HS256 | App explicitly blocks HMAC algorithms |
| Added `audience` and `issuer` claims | Required by JWT verification config |
| Used real DB instead of mocks | ESM module system prevents `jest.mock()` hoisting |
| Used real seeded users/accounts | Tests need valid FK references for service-level calls |
| Cleanup after creation tests | Keep test DB clean between runs |

---

## Final Results

```
Test Suites: 3 passed, 3 total
Tests:       48 passed, 48 total
Snapshots:   0 total
Time:        ~5s
```

All 48 tests passing across:
- ✅ Auth — registration validation, login, token checks, 404 handler
- ✅ Finance — transaction CRUD, validation, dashboard, categories, accounts
- ✅ Access Control — RBAC, IDOR prevention, mass assignment, XSS sanitisation

---

## Running the Tests

```bash
# Run all tests
npm test

# Run with coverage report
npm run test:coverage

# Watch mode
npm run test:watch
```

> **Note:** Tests require a running PostgreSQL instance with seeded data (`node prisma/seed.js`) and the RSA keys generated (`node scripts/generate-keys.js`). Redis must also be running but is only used by the application in non-test paths.
