/**
 * tests/auth.test.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Integration-style tests for authentication endpoints using Supertest.
 * Prisma and Redis are mocked via tests/setup.js.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { describe, test, expect, beforeAll, jest } from '@jest/globals';
import request from 'supertest';
import app from '../src/app.js';

// ── Pull the mocked prisma so we can control return values per test ──────────
const { default: prisma } = await import('../src/shared/config/database.js');

// ── Shared test helpers ──────────────────────────────────────────────────────
const POST = (path, body) => request(app).post(path).send(body).set('Content-Type', 'application/json');
const AUTH_BASE = '/api/v1/auth';

describe('Auth — Registration', () => {
  test('POST /register → 422 when body is empty', async () => {
    const res = await POST(`${AUTH_BASE}/register`, {});
    expect(res.status).toBe(422);
    expect(res.body.success).toBe(false);
    expect(res.body.code).toBe('VALIDATION_ERROR');
    expect(Array.isArray(res.body.errors)).toBe(true);
  });

  test('POST /register → 422 for weak password', async () => {
    const res = await POST(`${AUTH_BASE}/register`, {
      name: 'Alice', email: 'alice@example.com', password: 'weak',
    });
    expect(res.status).toBe(422);
    const fieldErrors = res.body.errors.map((e) => e.field);
    expect(fieldErrors).toContain('password');
  });

  test('POST /register → 422 for invalid email', async () => {
    const res = await POST(`${AUTH_BASE}/register`, {
      name: 'Alice', email: 'not-an-email', password: 'StrongPass1!',
    });
    expect(res.status).toBe(422);
  });

  test('POST /register → 422 when role is supplied (privilege escalation guard)', async () => {
    const res = await POST(`${AUTH_BASE}/register`, {
      name: 'Alice', email: 'alice@example.com', password: 'StrongPass1!@#', role: 'ADMIN',
    });
    expect(res.status).toBe(422);
  });

  test('POST /register → 409 for duplicate email', async () => {
    prisma.user.findUnique.mockResolvedValueOnce({ id: 'existing-user-id', email: 'alice@example.com' });
    const res = await POST(`${AUTH_BASE}/register`, {
      name: 'Alice', email: 'alice@example.com', password: 'StrongPass1!@#',
    });
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('DUPLICATE_EMAIL');
  });
});

describe('Auth — Login', () => {
  test('POST /login → 422 for missing credentials', async () => {
    const res = await POST(`${AUTH_BASE}/login`, {});
    expect(res.status).toBe(422);
  });

  test('POST /login → 401 for non-existent user', async () => {
    prisma.user.findUnique.mockResolvedValueOnce(null);
    const res = await POST(`${AUTH_BASE}/login`, {
      email: 'ghost@example.com', password: 'SomePass1!@#',
    });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('INVALID_CREDENTIALS');
  });
});

describe('Auth — Protected routes without token', () => {
  test('GET /api/v1/users → 401 without Authorization header', async () => {
    const res = await request(app).get('/api/v1/users');
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('AUTH_REQUIRED');
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
  const BEARER = (t) => ({ Authorization: `Bearer ${t}` });

  test('Malformed JWT → 401', async () => {
    const res = await request(app).get('/api/v1/users').set(BEARER('not.a.jwt'));
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
    expect(res.body.success).toBe(false);
  });
});
