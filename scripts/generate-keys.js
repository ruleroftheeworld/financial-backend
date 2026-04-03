#!/usr/bin/env node
/**
 * ─────────────────────────────────────────────────────────────
 * RSA KEY PAIR GENERATOR (Multi-Key / KID Support)
 * ─────────────────────────────────────────────────────────────
 *
 * Generates RSA-2048 key pairs for JWT RS256 signing with KID
 * (Key ID) support for seamless key rotation.
 *
 * Usage:
 *   node scripts/generate-keys.js                  # generates key1 (default)
 *   node scripts/generate-keys.js key1 key2        # generates key1 and key2
 *   node scripts/generate-keys.js --kid=mykey      # generates 'mykey'
 *
 * Output structure:
 *   keys/
 *     key1/
 *       private.pem   — RSA private key (signing)
 *       public.pem    — RSA public key (verification)
 *     key2/
 *       private.pem
 *       public.pem
 *
 * Backward compatibility:
 *   Also writes keys/jwt_private.pem and keys/jwt_public.pem
 *   as symlinks/copies of the first generated key for legacy
 *   compatibility.
 *
 * For Kubernetes:
 *   kubectl create secret generic jwt-keys \
 *     --from-file=key1-private=keys/key1/private.pem \
 *     --from-file=key1-public=keys/key1/public.pem \
 *     --from-file=key2-private=keys/key2/private.pem \
 *     --from-file=key2-public=keys/key2/public.pem
 * ─────────────────────────────────────────────────────────────
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const keysDir = path.join(__dirname, '..', 'keys');

// Parse arguments: support positional kids or --kid=name
let kids = process.argv.slice(2).map(arg => {
  if (arg.startsWith('--kid=')) return arg.slice(6);
  return arg;
}).filter(Boolean);

// Default: generate key1 and key2 if no args provided
if (kids.length === 0) {
  kids = ['key1', 'key2'];
}

// Validate KID names (alphanumeric + hyphens + underscores only)
const KID_PATTERN = /^[a-zA-Z0-9_-]+$/;
for (const kid of kids) {
  if (!KID_PATTERN.test(kid)) {
    console.error(`❌ Invalid KID "${kid}": must be alphanumeric with hyphens/underscores only`);
    process.exit(1);
  }
}

// Create root keys directory
fs.mkdirSync(keysDir, { recursive: true });

console.log('🔑 RSA-2048 Key Pair Generator (KID-aware)');
console.log('─'.repeat(50));

for (const kid of kids) {
  const kidDir = path.join(keysDir, kid);

  // Skip if key pair already exists (prevent accidental overwrite)
  const privatePath = path.join(kidDir, 'private.pem');
  const publicPath = path.join(kidDir, 'public.pem');

  if (fs.existsSync(privatePath) && fs.existsSync(publicPath)) {
    console.log(`⚠️  KID "${kid}" already exists at ${kidDir} — skipping`);
    console.log(`   To regenerate, delete the directory first.`);
    continue;
  }

  fs.mkdirSync(kidDir, { recursive: true });

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  fs.writeFileSync(privatePath, privateKey, { mode: 0o600 });
  fs.writeFileSync(publicPath, publicKey, { mode: 0o644 });

  console.log(`✅ KID "${kid}" generated:`);
  console.log(`   Private: ${privatePath}`);
  console.log(`   Public:  ${publicPath}`);
}

// Backward compatibility: copy first kid's keys to root level
const firstKid = kids[0];
const legacyPrivate = path.join(keysDir, 'jwt_private.pem');
const legacyPublic = path.join(keysDir, 'jwt_public.pem');
const firstPrivate = path.join(keysDir, firstKid, 'private.pem');
const firstPublic = path.join(keysDir, firstKid, 'public.pem');

if (fs.existsSync(firstPrivate) && fs.existsSync(firstPublic)) {
  fs.copyFileSync(firstPrivate, legacyPrivate);
  fs.copyFileSync(firstPublic, legacyPublic);
  console.log();
  console.log(`📋 Legacy compatibility: copied ${firstKid} → keys/jwt_*.pem`);
}

console.log();
console.log('─'.repeat(50));
console.log('📝 Add to .env:');
console.log(`   JWT_ACTIVE_KID=${firstKid}`);
for (const kid of kids) {
  console.log(`   JWT_KEY_${kid.toUpperCase()}_PRIVATE_FILE=./keys/${kid}/private.pem`);
  console.log(`   JWT_KEY_${kid.toUpperCase()}_PUBLIC_FILE=./keys/${kid}/public.pem`);
}
console.log();
console.log('⚠️  Keep private keys SECRET. Never commit to version control.');
console.log('   The keys/ directory is already in .gitignore.');
