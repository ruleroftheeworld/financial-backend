
import { OAuth2Client } from 'google-auth-library';
import AppError from '../../shared/utils/AppError.js';
import { google as googleConfig } from '../../shared/config/index.js';

const client = new OAuth2Client(
  googleConfig.clientId,
  googleConfig.clientSecret,
  googleConfig.redirectUri
);

export const getAuthUrl = () => {
  return client.generateAuthUrl({
    access_type: 'offline',
    scope: ['email', 'profile']
  });
};

export const exchangeCodeForIdToken = async (code) => {
  try {
    const { tokens } = await client.getToken(code);
    return tokens.id_token;
  } catch (error) {
    throw new AppError('Failed to exchange Google OAuth code', 400, 'GOOGLE_AUTH_FAILED');
  }
};

export const verifyGoogleIdToken = async (idToken) => {
  try {
    const ticket = await client.verifyIdToken({
      idToken,
      audience: googleConfig.clientId,
    });
    
    const payload = ticket.getPayload();
    
    if (!payload.email_verified) {
      throw new AppError('Google email not verified', 400, 'UNVERIFIED_EMAIL');
    }

    return {
      googleId: payload.sub,
      email: payload.email,
      name: payload.name,
    };
  } catch (error) {
    if (error.isAppError) throw error;
    throw new AppError('Invalid Google token', 401, 'INVALID_GOOGLE_TOKEN');
  }
};
