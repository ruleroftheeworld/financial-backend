/**
 * tests/finance.test.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Tests for Finance module endpoints.
 * All DB / Redis calls are mocked via tests/setup.js.
 * We use a pre-signed test token built from a known test secret.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { describe, test, expect, beforeAll, jest } from '@jest/globals';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../src/app.js';

const { default: prisma } = await import('../src/shared/config/database.js');

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
const TEST_USER = {
  id:           'user-test-uuid-0001',
  email:        'user@example.com',
  name:         'Test User',
  role:         'USER',
  tokenVersion: 0,
};

const TEST_ADMIN = {
  id:           'admin-test-uuid-0002',
  email:        'admin@example.com',
  name:         'Test Admin',
  role:         'ADMIN',
  tokenVersion: 0,
};

/**
 * Build a minimal signed access token that the authenticate middleware accepts.
 * Uses the same RS256 / HS256 flow; here we directly call the jwt util.
 * In a full integration test you'd call POST /auth/login instead.
 */
const mockAuthToken = (user) => {
  // The authenticate middleware pulls the user from DB (mocked below), so
  // the token itself just needs a valid structure with sub + jti.
  return jwt.sign(
    { sub: user.id, jti: 'session-test-jti', role: user.role, tokenVersion: 0 },
    'test-secret-not-production',
    { algorithm: 'HS256', expiresIn: '15m' }
  );
};

/**
 * Wire up mocks so authenticate() resolves successfully for a given user.
 */
const mockAuthenticated = (user) => {
  prisma.session.findUnique.mockResolvedValue({ id: 'session-test-jti', revoked: false });
  prisma.user.findUnique.mockResolvedValue(user);
};

const AUTH = (user) => ({ Authorization: `Bearer ${mockAuthToken(user)}` });
const FINANCE = '/api/v1/finance';

// ─────────────────────────────────────────────
// Transactions — Validation
// ─────────────────────────────────────────────
describe('POST /finance/transactions — input validation', () => {
  beforeAll(() => mockAuthenticated(TEST_USER));

  test('422 when body is empty', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .post(`${FINANCE}/transactions`)
      .set(AUTH(TEST_USER))
      .send({});
    expect(res.status).toBe(422);
    expect(res.body.code).toBe('VALIDATION_ERROR');
  });

  test('422 when amount is a float (not a string)', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .post(`${FINANCE}/transactions`)
      .set(AUTH(TEST_USER))
      .send({ type: 'EXPENSE', amount: 49.99, description: 'Coffee', date: new Date().toISOString() });
    expect(res.status).toBe(422);
    const fields = res.body.errors?.map((e) => e.field) || [];
    expect(fields).toContain('amount');
  });

  test('422 when amount is negative', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .post(`${FINANCE}/transactions`)
      .set(AUTH(TEST_USER))
      .send({ type: 'EXPENSE', amount: '-10.00', description: 'Refund', date: new Date().toISOString() });
    expect(res.status).toBe(422);
  });

  test('422 when amount has > 2 decimal places', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .post(`${FINANCE}/transactions`)
      .set(AUTH(TEST_USER))
      .send({ type: 'INCOME', amount: '100.999', description: 'Salary', date: new Date().toISOString() });
    expect(res.status).toBe(422);
  });

  test('422 when type is invalid', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .post(`${FINANCE}/transactions`)
      .set(AUTH(TEST_USER))
      .send({ type: 'TRANSFER', amount: '100.00', description: 'Move funds', date: new Date().toISOString() });
    expect(res.status).toBe(422);
  });

  test('422 when date is not ISO 8601', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .post(`${FINANCE}/transactions`)
      .set(AUTH(TEST_USER))
      .send({ type: 'INCOME', amount: '500.00', description: 'Bonus', date: '2026-13-45' });
    expect(res.status).toBe(422);
  });
});

describe('POST /finance/transactions — successful creation', () => {
  const mockTx = {
    id:          'tx-uuid-001',
    userId:      TEST_USER.id,
    type:        'INCOME',
    amount:      '5000.00',
    currency:    'USD',
    description: 'Monthly salary',
    date:        new Date(),
    category:    { id: 'cat-uuid-001', name: 'Salary', color: '#4CAF50', icon: '💼' },
    account:     null,
    deletedAt:   null,
    createdAt:   new Date(),
    updatedAt:   new Date(),
  };

  test('201 with valid payload', async () => {
    mockAuthenticated(TEST_USER);
    prisma.category.findFirst.mockResolvedValue({ id: 'cat-uuid-001', type: 'INCOME', userId: null });
    prisma.transaction.create.mockResolvedValue(mockTx);
    prisma.financeAuditLog.create.mockResolvedValue({});

    const res = await request(app)
      .post(`${FINANCE}/transactions`)
      .set(AUTH(TEST_USER))
      .send({
        type:        'INCOME',
        amount:      '5000.00',
        description: 'Monthly salary',
        date:        new Date().toISOString(),
        categoryId:  'cat-uuid-001',
      });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.transaction.type).toBe('INCOME');
    expect(res.body.data.transaction.amount).toBe('5000.00');
  });
});

// ─────────────────────────────────────────────
// Transactions — GET LIST
// ─────────────────────────────────────────────
describe('GET /finance/transactions', () => {
  test('200 with pagination envelope', async () => {
    mockAuthenticated(TEST_USER);
    prisma.transaction.findMany.mockResolvedValue([]);
    prisma.transaction.count.mockResolvedValue(0);

    const res = await request(app)
      .get(`${FINANCE}/transactions`)
      .set(AUTH(TEST_USER));

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('pagination');
    expect(res.body.data.pagination).toHaveProperty('total');
    expect(res.body.data.pagination).toHaveProperty('page');
  });

  test('422 for invalid page param', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .get(`${FINANCE}/transactions?page=-1`)
      .set(AUTH(TEST_USER));
    expect(res.status).toBe(422);
  });

  test('422 for invalid sortBy param', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .get(`${FINANCE}/transactions?sortBy=id`)
      .set(AUTH(TEST_USER));
    expect(res.status).toBe(422);
  });
});

// ─────────────────────────────────────────────
// Transactions — GET ONE
// ─────────────────────────────────────────────
describe('GET /finance/transactions/:id', () => {
  test('422 for non-UUID id', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .get(`${FINANCE}/transactions/not-a-uuid`)
      .set(AUTH(TEST_USER));
    expect(res.status).toBe(422);
  });

  test('404 when transaction not found', async () => {
    mockAuthenticated(TEST_USER);
    prisma.transaction.findFirst.mockResolvedValue(null);
    const res = await request(app)
      .get(`${FINANCE}/transactions/00000000-0000-0000-0000-000000000001`)
      .set(AUTH(TEST_USER));
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('TRANSACTION_NOT_FOUND');
  });

  test('200 when found and owned by user', async () => {
    mockAuthenticated(TEST_USER);
    const mockTx = { id: '00000000-0000-0000-0000-000000000001', userId: TEST_USER.id, type: 'EXPENSE', amount: '49.99', description: 'Coffee', date: new Date(), deletedAt: null, category: null, account: null };
    prisma.transaction.findFirst.mockResolvedValue(mockTx);

    const res = await request(app)
      .get(`${FINANCE}/transactions/00000000-0000-0000-0000-000000000001`)
      .set(AUTH(TEST_USER));

    expect(res.status).toBe(200);
    expect(res.body.data.transaction.id).toBe(mockTx.id);
  });
});

// ─────────────────────────────────────────────
// Dashboard
// ─────────────────────────────────────────────
describe('GET /finance/dashboard/summary', () => {
  test('200 with correct shape', async () => {
    mockAuthenticated(TEST_USER);
    prisma.transaction.groupBy.mockResolvedValue([
      { type: 'INCOME',  _sum: { amount: { toString: () => '8500.00' } }, _count: { id: 5 } },
      { type: 'EXPENSE', _sum: { amount: { toString: () => '3200.50' } }, _count: { id: 12 } },
    ]);

    const res = await request(app)
      .get(`${FINANCE}/dashboard/summary`)
      .set(AUTH(TEST_USER));

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('totalIncome');
    expect(res.body.data).toHaveProperty('totalExpense');
    expect(res.body.data).toHaveProperty('netBalance');
    expect(res.body.data).toHaveProperty('transactionCounts');
  });
});

// ─────────────────────────────────────────────
// Categories
// ─────────────────────────────────────────────
describe('POST /finance/categories — validation', () => {
  test('422 for missing name', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .post(`${FINANCE}/categories`)
      .set(AUTH(TEST_USER))
      .send({ type: 'INCOME' });
    expect(res.status).toBe(422);
  });

  test('422 for invalid color hex', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .post(`${FINANCE}/categories`)
      .set(AUTH(TEST_USER))
      .send({ name: 'Test', type: 'INCOME', color: 'red' });
    expect(res.status).toBe(422);
  });

  test('201 with valid payload', async () => {
    mockAuthenticated(TEST_USER);
    const cat = { id: 'cat-uuid-new', userId: TEST_USER.id, name: 'Bonus', type: 'INCOME', color: '#4CAF50', icon: '🎉', isDefault: false };
    prisma.category.create.mockResolvedValue(cat);
    prisma.financeAuditLog.create.mockResolvedValue({});

    const res = await request(app)
      .post(`${FINANCE}/categories`)
      .set(AUTH(TEST_USER))
      .send({ name: 'Bonus', type: 'INCOME', color: '#4CAF50', icon: '🎉' });

    expect(res.status).toBe(201);
    expect(res.body.data.category.name).toBe('Bonus');
  });
});

// ─────────────────────────────────────────────
// Accounts
// ─────────────────────────────────────────────
describe('POST /finance/accounts — validation', () => {
  test('422 for invalid account type', async () => {
    mockAuthenticated(TEST_USER);
    const res = await request(app)
      .post(`${FINANCE}/accounts`)
      .set(AUTH(TEST_USER))
      .send({ name: 'My Account', type: 'BITCOIN' });
    expect(res.status).toBe(422);
  });

  test('201 for valid checking account', async () => {
    mockAuthenticated(TEST_USER);
    const acc = { id: 'acc-uuid-001', userId: TEST_USER.id, name: 'Main Checking', type: 'CHECKING', balance: '0', currency: 'USD', isDefault: true };
    prisma.account.create.mockResolvedValue(acc);
    prisma.account.updateMany.mockResolvedValue({ count: 0 });
    prisma.financeAuditLog.create.mockResolvedValue({});

    const res = await request(app)
      .post(`${FINANCE}/accounts`)
      .set(AUTH(TEST_USER))
      .send({ name: 'Main Checking', type: 'CHECKING', isDefault: true });

    expect(res.status).toBe(201);
    expect(res.body.data.account.type).toBe('CHECKING');
  });
});
