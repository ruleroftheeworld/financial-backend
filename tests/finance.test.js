/**
 * tests/finance.test.js
 * Uses real DB for service-level tests (mocking doesn't work with ESM).
 * Validation tests (422) don't need DB — they fail before service layer.
 */

import { describe, test, expect, afterEach, jest } from '@jest/globals';

// ── Mock only Redis (rate limiter already disabled in test) ──────────────────
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

jest.mock('../src/shared/config/redis.js', () => ({ default: mockRedis }));
jest.mock('../src/shared/utils/logger.js', () => ({
  default: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(), http: jest.fn() },
}));

import request from 'supertest';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import app from '../src/app.js';
import prisma from '../src/shared/config/database.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const privateKey = fs.readFileSync(path.resolve(__dirname, '../keys/key1/private.pem'));

afterEach(() => jest.clearAllMocks());

// ─────────────────────────────────────────────
const TEST_USER_EMAIL = 'user@example.com';
let testUserId;
let testAccountId;

const makeToken = (userId, role = 'USER') =>
  jwt.sign(
    { sub: userId, jti: `jti-${userId}`, role, type: 'access', tokenVersion: 0 },
    privateKey,
    { algorithm: 'RS256', expiresIn: '15m', keyid: 'key1', audience: 'cloud-iam-users', issuer: 'cloud-iam-platform' }
  );

const FINANCE = '/api/v1/finance';

// ─────────────────────────────────────────────
// Setup — get real user and account from seeded DB
// ─────────────────────────────────────────────
const getTestUser = async () => {
  if (testUserId) return testUserId;
  const user = await prisma.user.findUnique({ where: { email: TEST_USER_EMAIL } });
  if (!user) throw new Error('Seed user not found. Run: node prisma/seed.js');
  testUserId = user.id;
  return testUserId;
};

const getTestAccount = async (userId) => {
  if (testAccountId) return testAccountId;
  const account = await prisma.account.findFirst({ where: { userId, deletedAt: null } });
  if (!account) throw new Error('No account found for test user. Run seed.');
  testAccountId = account.id;
  return testAccountId;
};

// ─────────────────────────────────────────────
// Validation tests — no DB needed (fail before service)
// ─────────────────────────────────────────────
describe('POST /finance/transactions — input validation', () => {
  let token;

  test('422 when body is empty', async () => {
    const userId = await getTestUser();
    token = makeToken(userId);
    const res = await request(app).post(`${FINANCE}/transactions`).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(422);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  test('422 when amount is a float (not a string)', async () => {
    const userId = await getTestUser();
    token = makeToken(userId);
    const res = await request(app).post(`${FINANCE}/transactions`).set('Authorization', `Bearer ${token}`)
      .send({ type: 'EXPENSE', amount: 49.99, description: 'Coffee', date: new Date().toISOString() });
    expect(res.status).toBe(422);
  });

  test('422 when amount is negative', async () => {
    const userId = await getTestUser();
    token = makeToken(userId);
    const res = await request(app).post(`${FINANCE}/transactions`).set('Authorization', `Bearer ${token}`)
      .send({ type: 'EXPENSE', amount: '-10.00', description: 'Refund', date: new Date().toISOString() });
    expect(res.status).toBe(422);
  });

  test('422 when amount has > 2 decimal places', async () => {
    const userId = await getTestUser();
    token = makeToken(userId);
    const res = await request(app).post(`${FINANCE}/transactions`).set('Authorization', `Bearer ${token}`)
      .send({ type: 'INCOME', amount: '100.999', description: 'Salary', date: new Date().toISOString() });
    expect(res.status).toBe(422);
  });

  test('422 when type is invalid', async () => {
    const userId = await getTestUser();
    token = makeToken(userId);
    const res = await request(app).post(`${FINANCE}/transactions`).set('Authorization', `Bearer ${token}`)
      .send({ type: 'TRANSFER', amount: '100.00', description: 'Move funds', date: new Date().toISOString() });
    expect(res.status).toBe(422);
  });

  test('422 when date is not ISO 8601', async () => {
    const userId = await getTestUser();
    token = makeToken(userId);
    const res = await request(app).post(`${FINANCE}/transactions`).set('Authorization', `Bearer ${token}`)
      .send({ type: 'INCOME', amount: '500.00', description: 'Bonus', date: '2026-13-45' });
    expect(res.status).toBe(422);
  });
});

describe('POST /finance/transactions — successful creation', () => {
  test('201 with valid payload', async () => {
    const userId = await getTestUser();
    const accountId = await getTestAccount(userId);
    const token = makeToken(userId);

    const res = await request(app).post(`${FINANCE}/transactions`).set('Authorization', `Bearer ${token}`)
      .send({
        type: 'INCOME',
        amount: '1.00',
        description: 'Jest test transaction',
        date: new Date().toISOString(),
        accountId,
      });

    expect(res.status).toBe(201);
    expect(res.body.data.transaction.type).toBe('INCOME');

    // Cleanup
    if (res.body.data?.transaction?.id) {
      await prisma.transaction.delete({ where: { id: res.body.data.transaction.id } }).catch(() => {});
    }
  });
});

describe('GET /finance/transactions', () => {
  test('200 with pagination envelope', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    const res = await request(app).get(`${FINANCE}/transactions`).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('pagination');
    expect(res.body.data.pagination).toHaveProperty('total');
  });

  test('422 for invalid page param', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    const res = await request(app).get(`${FINANCE}/transactions?page=-1`).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(422);
  });

  test('422 for invalid sortBy param', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    const res = await request(app).get(`${FINANCE}/transactions?sortBy=id`).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(422);
  });
});

describe('GET /finance/transactions/:id', () => {
  test('422 for non-UUID id', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    const res = await request(app).get(`${FINANCE}/transactions/not-a-uuid`).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(422);
  });

  test('404 when transaction not found', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    const res = await request(app)
      .get(`${FINANCE}/transactions/00000000-0000-4000-a000-000000000001`)
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('TRANSACTION_NOT_FOUND');
  });

  test('200 when found and owned by user', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    // Get a real transaction from DB
    const tx = await prisma.transaction.findFirst({ where: { userId, deletedAt: null } });
    if (!tx) return; // skip if no transactions seeded

    const res = await request(app)
      .get(`${FINANCE}/transactions/${tx.id}`)
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.data.transaction.id).toBe(tx.id);
  });
});

describe('GET /finance/dashboard/summary', () => {
  test('200 with correct shape', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    const res = await request(app).get(`${FINANCE}/dashboard/summary`).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('totalIncome');
    expect(res.body.data).toHaveProperty('totalExpense');
    expect(res.body.data).toHaveProperty('netBalance');
  });
});

describe('POST /finance/categories — validation', () => {
  test('422 for missing name', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    const res = await request(app).post(`${FINANCE}/categories`).set('Authorization', `Bearer ${token}`)
      .send({ type: 'INCOME' });
    expect(res.status).toBe(422);
  });

  test('422 for invalid color hex', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    const res = await request(app).post(`${FINANCE}/categories`).set('Authorization', `Bearer ${token}`)
      .send({ name: 'Test', type: 'INCOME', color: 'red' });
    expect(res.status).toBe(422);
  });

  test('201 with valid payload', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    const res = await request(app).post(`${FINANCE}/categories`).set('Authorization', `Bearer ${token}`)
      .send({ name: `JestCat-${Date.now()}`, type: 'INCOME', color: '#4CAF50' });
    expect(res.status).toBe(201);
    expect(res.body.data.category.type).toBe('INCOME');

    // Cleanup
    if (res.body.data?.category?.id) {
      await prisma.category.delete({ where: { id: res.body.data.category.id } }).catch(() => {});
    }
  });
});

describe('POST /finance/accounts — validation', () => {
  test('422 for invalid account type', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    const res = await request(app).post(`${FINANCE}/accounts`).set('Authorization', `Bearer ${token}`)
      .send({ name: 'My Account', type: 'BITCOIN' });
    expect(res.status).toBe(422);
  });

  test('201 for valid checking account', async () => {
    const userId = await getTestUser();
    const token = makeToken(userId);
    const res = await request(app).post(`${FINANCE}/accounts`).set('Authorization', `Bearer ${token}`)
      .send({ name: `JestAcc-${Date.now()}`, type: 'CHECKING' });
    expect(res.status).toBe(201);
    expect(res.body.data.account.type).toBe('CHECKING');

    // Cleanup
    if (res.body.data?.account?.id) {
      await prisma.account.delete({ where: { id: res.body.data.account.id } }).catch(() => {});
    }
  });
});
