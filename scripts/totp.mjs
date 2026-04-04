// DEV ONLY: TOTP generator for local MFA testing
// Not used in production

import speakeasy from 'speakeasy';
const code = speakeasy.totp({
  secret: 'MZLEWURBMZUTGKSUOU4XUZSBMZUXMM2PH5LSI3KEKQYFO5C6IBXA',
  encoding: 'base32'
});
console.log('TOTP code: - totp.mjs:9', code);