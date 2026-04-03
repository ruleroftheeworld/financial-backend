import winston from 'winston';

const { combine, timestamp, errors, json, colorize, printf } = winston.format;

// NOTE: Logger uses process.env.NODE_ENV directly (not centralized config)
// to avoid circular import issues — logger is used by the config module's
// downstream dependencies (database.js, redis.js) and must initialize
// without importing config/index.js.
const isProduction = process.env.NODE_ENV === 'production';

// ───────────────────────────────────────────────────────────
// Custom log format for development
// ───────────────────────────────────────────────────────────
const devFormat = printf(({ level, message, timestamp, stack, ...meta }) => {
  return `${timestamp} [${level}]: ${stack || message} ${
    Object.keys(meta).length ? JSON.stringify(meta) : ''
  }`;
});

// ───────────────────────────────────────────────────────────
// Logger instance
// ───────────────────────────────────────────────────────────
const logger = winston.createLogger({
  level: isProduction ? 'info' : 'debug',

  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    errors({ stack: true }),
    json()
  ),

  defaultMeta: {
    service: 'cloud-iam-platform',
  },

  transports: [
    // Console transport
    new winston.transports.Console({
      format: isProduction
        ? combine(timestamp(), json())
        : combine(colorize(), devFormat),
    }),
  ],
});

export default logger;