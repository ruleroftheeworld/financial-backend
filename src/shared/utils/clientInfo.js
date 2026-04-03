// 🔒 SEC-06: Use req.ip (respects trust proxy setting) instead of raw X-Forwarded-For
export const getClientIp = (req) => {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    req.ip
  );
};

export function extractClientInfo(req) {
  const ip = getClientIp(req);

  const userAgent =
    req.headers['user-agent'] || 'unknown';

  return { ip, userAgent };
}
