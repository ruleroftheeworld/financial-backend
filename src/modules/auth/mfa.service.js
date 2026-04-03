import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import prisma from '../../shared/config/database.js';
import AppError from '../../shared/utils/AppError.js';
import { logSecurityEvent } from './audit.service.js';
import { encrypt, decrypt } from '../../shared/utils/cipher.js';
import { encryption } from '../../shared/config/index.js';

export const setupMfa = async (userId) => {
  const secret = speakeasy.generateSecret({
    name: `CloudIAM (${userId})`,
  });

  const qr = await qrcode.toDataURL(secret.otpauth_url);

  // Store encrypted secret using active key version from config
  const version = encryption.activeKeyVersion;

  const encryptedSecret = encrypt(secret.base32, version);

  await prisma.user.update({
    where: { id: userId },
    data: { 
      totpSecret: encryptedSecret, 
      totpEnabled: false,
      totpSecretKeyVersion: version
    }
  });

  return {
    qr,
    // 🔒 SEC-10: manual plain-text key removed. Return ONLY QR/URI to prevent leakage.
    otpauth_url: secret.otpauth_url
  };
};

export const verifyMfa = async (userId, code) => {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  
  if (!user || !user.totpSecret) {
    throw new AppError('MFA secret not found. Setup first.', 400, 'MFA_NOT_SETUP');
  }

  if (user.totpSecret && !user.totpSecretKeyVersion) {
    throw new AppError(
      'Invalid encryption state',
      500,
      'CRYPTO_STATE_INVALID'
    );
  }

  if (!user.totpSecretKeyVersion) {
    throw new AppError('MFA key version missing', 500, 'MFA_KEY_ERROR');
  }

  const decryptedSecret = decrypt(user.totpSecret, user.totpSecretKeyVersion);

  const verified = speakeasy.totp.verify({
    secret: decryptedSecret,
    encoding: 'base32',
    token: code,
    window: 1, // Allow 30 seconds drift before/after
  });

  if (!verified) {
    // Audit log failure
    await logSecurityEvent({
      userId, action: 'MFA_ENABLED', status: 'FAILED'
    });
    throw new AppError('Invalid MFA code', 400, 'INVALID_MFA_CODE');
  }

  // Finalize setup
  await prisma.user.update({
    where: { id: userId },
    data: { totpEnabled: true },
  });

  await logSecurityEvent({
    userId, action: 'MFA_ENABLED', status: 'SUCCESS'
  });

  return { success: true };
};
