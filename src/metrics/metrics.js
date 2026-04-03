import client from 'prom-client';

const register = new client.Registry();

// Enable default metrics (e.g., CPU, memory, event loop lag, etc.)
client.collectDefaultMetrics({ register });

// ─────────────────────────────────────────────
// LOGIN & AUTH METRICS
// ─────────────────────────────────────────────
export const loginCounter = new client.Counter({
  name: 'iam_login_requests_total',
  help: 'Total number of login requests',
  labelNames: ['status'],
});
register.registerMetric(loginCounter);

export const loginDuration = new client.Histogram({
  name: 'iam_login_duration_seconds',
  help: 'Duration of login requests in seconds',
  buckets: [0.1, 0.3, 0.5, 1, 2, 5],
});
register.registerMetric(loginDuration);

export const accountLockCounter = new client.Counter({
  name: 'iam_account_locks_total',
  help: 'Total account lockouts triggered by brute-force protection',
  labelNames: ['reason'],
});
register.registerMetric(accountLockCounter);

// ─────────────────────────────────────────────
// MFA METRICS
// ─────────────────────────────────────────────
export const mfaCounter = new client.Counter({
  name: 'iam_mfa_login_attempts_total',
  help: 'Total number of MFA login attempts',
  labelNames: ['status'],
});
register.registerMetric(mfaCounter);

// ─────────────────────────────────────────────
// JWT SECURITY METRICS
// ─────────────────────────────────────────────
export const jwtVerificationFailures = new client.Counter({
  name: 'iam_jwt_verification_failures_total',
  help: 'Total JWT verification failures by reason',
  labelNames: ['reason'],
});
register.registerMetric(jwtVerificationFailures);

// ─────────────────────────────────────────────
// RATE LIMITING METRICS
// ─────────────────────────────────────────────
export const rateLimitCounter = new client.Counter({
  name: 'iam_rate_limit_hits_total',
  help: 'Total number of rate limit hits',
  labelNames: ['type'],
});
register.registerMetric(rateLimitCounter);

// ─────────────────────────────────────────────
// SESSION SECURITY METRICS
// ─────────────────────────────────────────────
export const sessionSecurityCounter = new client.Counter({
  name: 'iam_session_security_events_total',
  help: 'Session security events: reuse detection, compromise, revocation',
  labelNames: ['event'],
});
register.registerMetric(sessionSecurityCounter);

// ─────────────────────────────────────────────
// AUTHORIZATION METRICS (RBAC / ABAC / IDOR)
// ─────────────────────────────────────────────
export const authorizationFailures = new client.Counter({
  name: 'iam_authorization_failures_total',
  help: 'Authorization denials by type (RBAC, ABAC policy, IDOR)',
  labelNames: ['type'],
});
register.registerMetric(authorizationFailures);

// ─────────────────────────────────────────────
// INPUT VALIDATION METRICS (mass assignment etc.)
// ─────────────────────────────────────────────
export const validationFailures = new client.Counter({
  name: 'iam_validation_failures_total',
  help: 'Input validation failures (schema violations, mass assignment blocks)',
  labelNames: ['endpoint'],
});
register.registerMetric(validationFailures);

// ─────────────────────────────────────────────
// AUTH MIDDLEWARE METRICS
// ─────────────────────────────────────────────
export const authFailureCounter = new client.Counter({
  name: 'iam_auth_failures_total',
  help: 'Authentication middleware failures by reason',
  labelNames: ['reason'],
});
register.registerMetric(authFailureCounter);

// ─────────────────────────────────────────────
// ACTIVE DEFENSE METRICS (IP Bans)
// ─────────────────────────────────────────────
export const ipBanCounter = new client.Counter({
  name: 'iam_ip_bans_total',
  help: 'Total number of IP bans issued by active defense',
  labelNames: ['reason', 'severity'],
});
register.registerMetric(ipBanCounter);

// ─────────────────────────────────────────────
// GLOBAL HTTP METRICS
// ─────────────────────────────────────────────
export const requestCounter = new client.Counter({
  name: 'iam_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status'],
});
register.registerMetric(requestCounter);

// ─────────────────────────────────────────────
// FINANCE MODULE METRICS
// ─────────────────────────────────────────────
export const financeTransactionCounter = new client.Counter({
  name: 'finance_transactions_total',
  help: 'Total financial transactions by action and type',
  labelNames: ['action', 'type'],
});
register.registerMetric(financeTransactionCounter);

export const financeDashboardCacheHits = new client.Counter({
  name: 'finance_dashboard_cache_hits_total',
  help: 'Dashboard cache hits vs misses',
  labelNames: ['endpoint', 'result'],
});
register.registerMetric(financeDashboardCacheHits);

export const financeApiDuration = new client.Histogram({
  name: 'finance_api_duration_seconds',
  help: 'Duration of finance API requests in seconds',
  labelNames: ['endpoint', 'method'],
  buckets: [0.05, 0.1, 0.2, 0.5, 1, 2],
});
register.registerMetric(financeApiDuration);

export { register };

