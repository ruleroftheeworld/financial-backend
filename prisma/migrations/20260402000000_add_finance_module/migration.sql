-- ────────────────────────────────────────────────────────────────────────────
-- Migration: Add Finance Module (Accounts, Categories, Transactions, Audit)
-- ────────────────────────────────────────────────────────────────────────────

-- Create AccountType enum
CREATE TYPE "AccountType" AS ENUM (
  'CHECKING',
  'SAVINGS',
  'CREDIT',
  'INVESTMENT',
  'WALLET'
);

-- Create TransactionType enum
CREATE TYPE "TransactionType" AS ENUM (
  'INCOME',
  'EXPENSE'
);

-- Create accounts table
CREATE TABLE "accounts" (
  "id"          TEXT            NOT NULL DEFAULT gen_random_uuid()::text,
  "userId"      TEXT            NOT NULL,
  "name"        TEXT            NOT NULL,
  "type"        "AccountType"   NOT NULL,
  "balance"     DECIMAL(20, 2)  NOT NULL DEFAULT 0,
  "currency"    TEXT            NOT NULL DEFAULT 'USD',
  "description" TEXT,
  "isDefault"   BOOLEAN         NOT NULL DEFAULT false,
  "deletedAt"   TIMESTAMP(3),
  "createdAt"   TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"   TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "accounts_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "accounts_userId_idx" ON "accounts"("userId");

ALTER TABLE "accounts"
  ADD CONSTRAINT "accounts_userId_fkey"
  FOREIGN KEY ("userId")
  REFERENCES "users"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

-- Create categories table
CREATE TABLE "categories" (
  "id"        TEXT              NOT NULL DEFAULT gen_random_uuid()::text,
  "userId"    TEXT,
  "name"      TEXT              NOT NULL,
  "type"      "TransactionType" NOT NULL,
  "color"     TEXT,
  "icon"      TEXT,
  "isDefault" BOOLEAN           NOT NULL DEFAULT false,
  "deletedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "categories_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "categories_userId_idx" ON "categories"("userId");

ALTER TABLE "categories"
  ADD CONSTRAINT "categories_userId_fkey"
  FOREIGN KEY ("userId")
  REFERENCES "users"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

-- Create transactions table
CREATE TABLE "transactions" (
  "id"          TEXT              NOT NULL DEFAULT gen_random_uuid()::text,
  "userId"      TEXT              NOT NULL,
  "accountId"   TEXT,
  "categoryId"  TEXT,
  "type"        "TransactionType" NOT NULL,
  "amount"      DECIMAL(20, 2)    NOT NULL,
  "currency"    TEXT              NOT NULL DEFAULT 'USD',
  "description" TEXT              NOT NULL,
  "notes"       TEXT,
  "date"        TIMESTAMP(3)      NOT NULL,
  "deletedAt"   TIMESTAMP(3),
  "createdAt"   TIMESTAMP(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"   TIMESTAMP(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "transactions_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "transactions_userId_idx"      ON "transactions"("userId");
CREATE INDEX "transactions_userId_date_idx" ON "transactions"("userId", "date");
CREATE INDEX "transactions_userId_type_idx" ON "transactions"("userId", "type");
CREATE INDEX "transactions_categoryId_idx"  ON "transactions"("categoryId");
CREATE INDEX "transactions_accountId_idx"   ON "transactions"("accountId");

ALTER TABLE "transactions"
  ADD CONSTRAINT "transactions_userId_fkey"
  FOREIGN KEY ("userId")
  REFERENCES "users"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "transactions"
  ADD CONSTRAINT "transactions_accountId_fkey"
  FOREIGN KEY ("accountId")
  REFERENCES "accounts"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "transactions"
  ADD CONSTRAINT "transactions_categoryId_fkey"
  FOREIGN KEY ("categoryId")
  REFERENCES "categories"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

-- Create finance_audit_logs table
CREATE TABLE "finance_audit_logs" (
  "id"            TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
  "userId"        TEXT         NOT NULL,
  "transactionId" TEXT,
  "action"        TEXT         NOT NULL,
  "before"        JSONB,
  "after"         JSONB,
  "ip"            TEXT,
  "userAgent"     TEXT,
  "createdAt"     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "finance_audit_logs_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "finance_audit_logs_userId_idx"        ON "finance_audit_logs"("userId");
CREATE INDEX "finance_audit_logs_transactionId_idx" ON "finance_audit_logs"("transactionId");

ALTER TABLE "finance_audit_logs"
  ADD CONSTRAINT "finance_audit_logs_userId_fkey"
  FOREIGN KEY ("userId")
  REFERENCES "users"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "finance_audit_logs"
  ADD CONSTRAINT "finance_audit_logs_transactionId_fkey"
  FOREIGN KEY ("transactionId")
  REFERENCES "transactions"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

-- ────────────────────────────────────────────────────────────────────────────
-- Seed default categories (system-wide, userId = NULL)
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO "categories" ("id", "name", "type", "color", "icon", "isDefault", "updatedAt") VALUES
  (gen_random_uuid()::text, 'Salary',       'INCOME',  '#4CAF50', '💼', true, CURRENT_TIMESTAMP),
  (gen_random_uuid()::text, 'Freelance',    'INCOME',  '#8BC34A', '💻', true, CURRENT_TIMESTAMP),
  (gen_random_uuid()::text, 'Investment',   'INCOME',  '#009688', '📈', true, CURRENT_TIMESTAMP),
  (gen_random_uuid()::text, 'Other Income', 'INCOME',  '#00BCD4', '💰', true, CURRENT_TIMESTAMP),
  (gen_random_uuid()::text, 'Food',         'EXPENSE', '#FF5722', '🍔', true, CURRENT_TIMESTAMP),
  (gen_random_uuid()::text, 'Transport',    'EXPENSE', '#FF9800', '🚗', true, CURRENT_TIMESTAMP),
  (gen_random_uuid()::text, 'Housing',      'EXPENSE', '#795548', '🏠', true, CURRENT_TIMESTAMP),
  (gen_random_uuid()::text, 'Healthcare',   'EXPENSE', '#F44336', '🏥', true, CURRENT_TIMESTAMP),
  (gen_random_uuid()::text, 'Shopping',     'EXPENSE', '#E91E63', '🛍️', true, CURRENT_TIMESTAMP),
  (gen_random_uuid()::text, 'Education',    'EXPENSE', '#9C27B0', '📚', true, CURRENT_TIMESTAMP),
  (gen_random_uuid()::text, 'Entertainment','EXPENSE', '#3F51B5', '🎬', true, CURRENT_TIMESTAMP),
  (gen_random_uuid()::text, 'Utilities',    'EXPENSE', '#607D8B', '💡', true, CURRENT_TIMESTAMP);
