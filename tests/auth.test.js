/**
 * tests/auth.test.js
 */

import { describe, test, expect, afterEach, jest } from '@jest/globals';

// ── Inline mocks ─────────────────────────────────────────────────────────────
const mockPrisma = {
  user:            { findUnique: jest.fn(), findMany: jest.fn(), create: jest.fn(), update: jest.fn(), updateMany: jest.fn(), count: jest.fn(), groupBy: jest.fn(), upsert: jest.fn() },
  session:         { findUnique: jest.fn(), findFirst: jest.fn(), create: jest.fn(), update: jest.fn(), updateMany: jest.fn(), count: jest.fn() },
  transaction:     { findFirst: jest.fn(), findMany: jest.fn(), create: jest.fn(), update: jest.fn(), count: jest.fn(), groupBy: jest.fn() },
  category:        { findFirst: jest.fn(), findMany: jest.fn(), create: jest.fn(), update: jest.fn(), count: jest.fn() },
  account:         { findFirst: jest.fn(), findMany: jest.fn(), create: jest.fn(), update: jest.fn(), updateMany: jest.fn() },
  financeAuditLog: { create: jest.fn(), findMany: jest.fn() },
  auditLog:        { create: jest.fn() },
  $connect:        jest.fn().mockResolvedValue(undefined),
  $disconnect:     jest.fn().mockResolvedValue(undefined),
  $transaction:    jest.fn((fn) => fn(mockPrisma)),
  $queryRaw:       jest.fn().mockResolvedValue([{ net_balance: '0.00' }]),
};

const mockRedis = {
  get: jest.fn().mockResolvedValue(null),
  setex: jest.fn().mockResolvedValue('OK'),
  set: jest.fn().mockResolvedValue('OK'),
  del: jest.fn().mockResolvedValue(1),
  keys: jest.fn().mockResolvedValue([]),
  call: jest.fn().mockResolvedValue(null),
  xadd: jest.fn().mockResolvedValue('0-0'),
  on: jest.fn(),
  ping: jest.fn().mockResolvedValue('PONG'),
};

jest.mock('../src/shared/config/database.js', () => ({ default: mockPrisma }));
jest.mock('../src/shared/config/redis.js', () => ({ default: mockRedis }));
jest.mock('../src/shared/utils/logger.js', () => ({
  default: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(), http: jest.fn() },
}));

import request from 'supertest';
import app from '../src/app.js';

afterEach(() => jest.clearAllMocks());

const POST = (path, body) => request(app).post(path).send(body).set('Content-Type', 'application/json');
const AUTH_BASE = '/api/v1/auth';

describe('Auth — Registration', () => {
  test('POST /register → 422 when body is empty', async () => {
    const res = await POST(`${AUTH_BASE}/register`, {});
    expect(res.status).toBe(422);
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  test('POST /register → 422 for weak password', async () => {
    const res = await POST(`${AUTH_BASE}/register`, { name: 'Alice', email: 'alice@example.com', password: 'weak' });
    expect(res.status).toBe(422);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  test('POST /register → 422 for invalid email', async () => {
    const res = await POST(`${AUTH_BASE}/register`, { name: 'Alice', email: 'not-an-email', password: 'StrongPass1!' });
    expect(res.status).toBe(422);
  });

  test('POST /register → 422 when role is supplied (privilege escalation guard)', async () => {
    const res = await POST(`${AUTH_BASE}/register`, { name: 'Alice', email: 'alice@example.com', password: 'StrongPass1!@#', role: 'ADMIN' });
    expect(res.status).toBe(422);
  });

  test('POST /register → 409 for duplicate email', async () => {
    mockPrisma.user.findUnique.mockResolvedValueOnce({ id: 'existing-user-id', email: 'alice@example.com' });
    const res = await POST(`${AUTH_BASE}/register`, { name: 'Alice', email: 'alice@example.com', password: 'StrongPass1!@#' });
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('DUPLICATE_EMAIL');
  });
});

describe('Auth — Login', () => {
  test('POST /login → 422 for missing credentials', async () => {
    const res = await POST(`${AUTH_BASE}/login`, {});
    expect(res.status).toBe(422);
  });

  test('POST /login → 401 for non-existent user', async () => {
    mockPrisma.user.findUnique.mockResolvedValueOnce(null);
    const res = await POST(`${AUTH_BASE}/login`, { email: 'ghost@example.com', password: 'SomePass1!@#' });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_CREDENTIALS');
  });
});

describe('Auth — Protected routes without token', () => {
  test('GET /api/v1/users → 401 without Authorization header', async () => {
    const res = await request(app).get('/api/v1/users');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH_REQUIRED');
  });

  test('GET /api/v1/finance/transactions → 401 without token', async () => {
    const res = await request(app).get('/api/v1/finance/transactions');
    expect(res.status).toBe(401);
  });

  test('GET /api/v1/finance/dashboard/summary → 401 without token', async () => {
    const res = await request(app).get('/api/v1/finance/dashboard/summary');
    expect(res.status).toBe(401);
  });
});

describe('Auth — Malformed tokens', () => {
  test('Malformed JWT → 401', async () => {
    const res = await request(app).get('/api/v1/users').set({ Authorization: 'Bearer not.a.jwt' });
    expect(res.status).toBe(401);
  });

  test('Empty bearer → 401', async () => {
    const res = await request(app).get('/api/v1/users').set({ Authorization: 'Bearer ' });
    expect(res.status).toBe(401);
  });
});

describe('Health Check', () => {
  test('GET /health → 200 with uptime', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(typeof res.body.uptime).toBe('number');
  });
});

describe('404 Handler', () => {
  test('Unknown route → 404', async () => {
    const res = await request(app).get('/api/v1/does-not-exist');
    expect(res.status).toBe(404);
    expect(res.body.error).toBeDefined();
  });
});
