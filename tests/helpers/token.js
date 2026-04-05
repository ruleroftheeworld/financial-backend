import fs from 'fs';
import jwt from 'jsonwebtoken';

const privateKey = fs.readFileSync('./keys/key1/private.pem');

export const makeToken = (user) =>
  jwt.sign(
    { sub: user.id, jti: `jti-${user.id}`, role: user.role, type: 'access', tokenVersion: 0 },
    privateKey,
    { algorithm: 'RS256', expiresIn: '15m', keyid: 'key1' }
  );