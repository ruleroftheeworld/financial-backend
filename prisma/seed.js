import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import speakeasy from 'speakeasy';
import { encrypt } from '../src/shared/utils/cipher.js';
import config from '../src/shared/config/index.js';

const prisma = new PrismaClient();

const ARGON2_OPTIONS = {
  type:        argon2.argon2id,
  memoryCost:  config.hashing.memoryCost,
  timeCost:    config.hashing.timeCost,
  parallelism: config.hashing.parallelism,
  hashLength:  config.hashing.hashLength,
};

const DEFAULT_PASSWORDS = {
  ADMIN:            config.seed.adminPassword,
  SECURITY_ANALYST: config.seed.analystPassword,
  USER:             config.seed.userPassword,
};

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
const daysAgo = (n) => {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
};

const randomBetween = (min, max) =>
  (Math.random() * (max - min) + min).toFixed(2);

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────
async function main() {
  // ── 1. Seed users ───────────────────────────
  const usersData = [
    { name: 'Super Admin',           email: 'admin@example.com',    role: 'ADMIN',            password: DEFAULT_PASSWORDS.ADMIN },
    { name: 'Security Analyst',      email: 'analyst@example.com',  role: 'SECURITY_ANALYST', password: DEFAULT_PASSWORDS.SECURITY_ANALYST },
    { name: 'Regular User',          email: 'user@example.com',     role: 'USER',             password: DEFAULT_PASSWORDS.USER },
    { name: 'Admin Attack (MFA Test)',email: config.seed.mfaTargetEmail, role: 'ADMIN', password: config.seed.mfaTargetPassword || DEFAULT_PASSWORDS.ADMIN, totp: true },
  ];

  const createdUsers = {};

  for (const userData of usersData) {
    const hashedPassword = await argon2.hash(userData.password, ARGON2_OPTIONS);
    let totpData = {};
    if (userData.totp) {
      const secret  = speakeasy.generateSecret().base32;
      const version = config.encryption.activeKeyVersion;
      totpData = { totpSecret: encrypt(secret, version), totpEnabled: true, totpSecretKeyVersion: version };
    }
    const user = await prisma.user.upsert({
      where:  { email: userData.email.toLowerCase().trim() },
      update: { password: hashedPassword, ...totpData },
      create: { name: userData.name, email: userData.email.toLowerCase().trim(), password: hashedPassword, role: userData.role, ...totpData },
    });
    createdUsers[userData.role] = user;
    console.log(`✅ Seeded user: ${user.email} [${user.role}]`);
  }

  // ── 2. Seed system categories (idempotent) ──
  const systemCategories = [
    { name: 'Salary',        type: 'INCOME',  color: '#4CAF50', icon: '💼' },
    { name: 'Freelance',     type: 'INCOME',  color: '#8BC34A', icon: '💻' },
    { name: 'Investment',    type: 'INCOME',  color: '#009688', icon: '📈' },
    { name: 'Other Income',  type: 'INCOME',  color: '#00BCD4', icon: '💰' },
    { name: 'Food',          type: 'EXPENSE', color: '#FF5722', icon: '🍔' },
    { name: 'Transport',     type: 'EXPENSE', color: '#FF9800', icon: '🚗' },
    { name: 'Housing',       type: 'EXPENSE', color: '#795548', icon: '🏠' },
    { name: 'Healthcare',    type: 'EXPENSE', color: '#F44336', icon: '🏥' },
    { name: 'Shopping',      type: 'EXPENSE', color: '#E91E63', icon: '🛍️' },
    { name: 'Education',     type: 'EXPENSE', color: '#9C27B0', icon: '📚' },
    { name: 'Entertainment', type: 'EXPENSE', color: '#3F51B5', icon: '🎬' },
    { name: 'Utilities',     type: 'EXPENSE', color: '#607D8B', icon: '💡' },
  ];

  const seededCategories = {};
  for (const cat of systemCategories) {
    const existing = await prisma.category.findFirst({
      where: { name: cat.name, userId: null, isDefault: true },
    });
    const category = existing
      ? existing
      : await prisma.category.create({ data: { ...cat, userId: null, isDefault: true } });
    seededCategories[cat.name] = category;
  }
  console.log(`✅ Seeded ${Object.keys(seededCategories).length} system categories`);

  // ── 3. Seed sample finance data for regular user ──
  const user = createdUsers['USER'];
  if (!user) { console.log('⚠️  No USER found — skipping finance seed'); return; }

  // Create a checking account for the user
  let checkingAccount = await prisma.account.findFirst({ where: { userId: user.id, name: 'Main Checking' } });
  if (!checkingAccount) {
    checkingAccount = await prisma.account.create({
      data: { userId: user.id, name: 'Main Checking', type: 'CHECKING', currency: 'USD', isDefault: true, balance: '0' },
    });
  }

  let savingsAccount = await prisma.account.findFirst({ where: { userId: user.id, name: 'Savings' } });
  if (!savingsAccount) {
    savingsAccount = await prisma.account.create({
      data: { userId: user.id, name: 'Savings', type: 'SAVINGS', currency: 'USD', isDefault: false, balance: '0' },
    });
  }
  console.log(`✅ Seeded accounts for ${user.email}`);

  // Sample transactions over the last 90 days
  const txTemplates = [
    // INCOME
    { type: 'INCOME',  catName: 'Salary',        desc: 'Monthly salary',        minAmt: 5000, maxAmt: 5000, freqDays: 30 },
    { type: 'INCOME',  catName: 'Freelance',      desc: 'Freelance project',     minAmt: 500,  maxAmt: 2000, freqDays: 14 },
    { type: 'INCOME',  catName: 'Investment',     desc: 'Dividend payment',      minAmt: 50,   maxAmt: 300,  freqDays: 30 },
    // EXPENSE
    { type: 'EXPENSE', catName: 'Housing',        desc: 'Monthly rent',          minAmt: 1200, maxAmt: 1200, freqDays: 30 },
    { type: 'EXPENSE', catName: 'Food',           desc: 'Grocery store',         minAmt: 40,   maxAmt: 120,  freqDays: 7  },
    { type: 'EXPENSE', catName: 'Transport',      desc: 'Gas / Uber',            minAmt: 15,   maxAmt: 60,   freqDays: 5  },
    { type: 'EXPENSE', catName: 'Entertainment',  desc: 'Streaming subscription',minAmt: 10,   maxAmt: 30,   freqDays: 30 },
    { type: 'EXPENSE', catName: 'Utilities',      desc: 'Electric bill',         minAmt: 80,   maxAmt: 150,  freqDays: 30 },
    { type: 'EXPENSE', catName: 'Healthcare',     desc: 'Pharmacy',              minAmt: 20,   maxAmt: 80,   freqDays: 20 },
    { type: 'EXPENSE', catName: 'Shopping',       desc: 'Online shopping',       minAmt: 25,   maxAmt: 200,  freqDays: 10 },
  ];

  let txCount = 0;
  for (const tmpl of txTemplates) {
    const cat = seededCategories[tmpl.catName];
    if (!cat) continue;

    // Generate transactions every freqDays over 90-day window
    let offsetDays = 0;
    while (offsetDays <= 90) {
      const existingTx = await prisma.transaction.findFirst({
        where: { userId: user.id, description: tmpl.desc, date: { gte: daysAgo(offsetDays + 2), lte: daysAgo(Math.max(0, offsetDays - 2)) } },
      });
      if (!existingTx) {
        await prisma.transaction.create({
          data: {
            userId:      user.id,
            accountId:   checkingAccount.id,
            categoryId:  cat.id,
            type:        tmpl.type,
            amount:      randomBetween(tmpl.minAmt, tmpl.maxAmt),
            currency:    'USD',
            description: tmpl.desc,
            date:        daysAgo(offsetDays),
          },
        });
        txCount++;
      }
      offsetDays += tmpl.freqDays;
    }
  }
  console.log(`✅ Seeded ${txCount} sample transactions for ${user.email}`);
}

main()
  .catch((e) => { console.error('❌ Seed failed:', e.message); process.exit(1); })
  .finally(async () => { await prisma.$disconnect(); });
