/**
 * tests/setup.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Global test setup: mocks external I/O so unit and integration tests do not
 * depend on a live database or Redis.
 *
 * For true integration tests against a real Postgres+Redis, replace these mocks
 * with testcontainers or a dedicated test DB URL in .env.test.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { jest } from '@jest/globals';

// ── Mock Prisma ─────────────────────────────────────────────────────────────
jest.mock('../src/shared/config/database.js', () => {
  const mockPrisma = {
    user: {
      findUnique:  jest.fn(),
      findMany:    jest.fn(),
      create:      jest.fn(),
      update:      jest.fn(),
      updateMany:  jest.fn(),
      count:       jest.fn(),
      groupBy:     jest.fn(),
      upsert:      jest.fn(),
    },
    session: {
      findUnique:  jest.fn(),
      findFirst:   jest.fn(),
      create:      jest.fn(),
      update:      jest.fn(),
      updateMany:  jest.fn(),
      count:       jest.fn(),
    },
    transaction: {
      findFirst:   jest.fn(),
      findMany:    jest.fn(),
      create:      jest.fn(),
      update:      jest.fn(),
      count:       jest.fn(),
      groupBy:     jest.fn(),
    },
    category: {
      findFirst:   jest.fn(),
      findMany:    jest.fn(),
      create:      jest.fn(),
      update:      jest.fn(),
      count:       jest.fn(),
    },
    account: {
      findFirst:   jest.fn(),
      findMany:    jest.fn(),
      create:      jest.fn(),
      update:      jest.fn(),
      updateMany:  jest.fn(),
    },
    financeAuditLog: {
      create:      jest.fn(),
      findMany:    jest.fn(),
    },
    auditLog: {
      create:      jest.fn(),
    },
    $connect:      jest.fn().mockResolvedValue(undefined),
    $disconnect:   jest.fn().mockResolvedValue(undefined),
    $transaction:  jest.fn((fn) => fn(mockPrisma)),
    $queryRaw:     jest.fn().mockResolvedValue([{ net_balance: '0.00' }]),
  };
  return { default: mockPrisma };
});

// ── Mock Redis ───────────────────────────────────────────────────────────────
jest.mock('../src/shared/config/redis.js', () => {
  const mockRedis = {
    get:      jest.fn().mockResolvedValue(null),
    setex:    jest.fn().mockResolvedValue('OK'),
    del:      jest.fn().mockResolvedValue(1),
    keys:     jest.fn().mockResolvedValue([]),
    call:     jest.fn().mockResolvedValue(null),
    xadd:     jest.fn().mockResolvedValue('0-0'),
    on:       jest.fn(),
    ping:     jest.fn().mockResolvedValue('PONG'),
  };
  return { default: mockRedis };
});

// ── Silence logger during tests ──────────────────────────────────────────────
jest.mock('../src/shared/utils/logger.js', () => ({
  default: {
    info:  jest.fn(),
    warn:  jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    http:  jest.fn(),
  },
}));

// ── Reset all mocks between tests ────────────────────────────────────────────
afterEach(() => {
  jest.clearAllMocks();
});
