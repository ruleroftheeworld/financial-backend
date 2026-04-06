import 'dotenv/config';
import config from './shared/config/index.js';  // Must import AFTER dotenv
import app from './app.js';
import prisma from './shared/config/database.js';
import logger from './shared/utils/logger.js';

const PORT = config.app.port;

// Warn (not throw) — internal routes will fail-secure but main service stays up
if (!config.internal.serviceToken) {
  logger.warn(
    '⚠️  INTERNAL_SERVICE_TOKEN is not set. ' +
    'Internal service-to-service routes will reject all requests.'
  );
}

const shutdown = async (signal, server) => {
  logger.info(`${signal} received. Shutting down gracefully...`);

  server.close(async () => {
    logger.info('HTTP server closed.');

    try {
      await prisma.$disconnect();
      logger.info('Database disconnected.');
    } catch (err) {
      logger.error('Error during DB disconnect', {
        message: err.message,
        stack: err.stack,
      });
    }

    process.exit(0);
  });

  setTimeout(() => {
    logger.error('Forced shutdown after timeout.');
    process.exit(1);
  }, 10000);
};

const startServer = async () => {
  try {
    await prisma.$connect();
    logger.info('✅ Database connected');

    const server = app.listen(PORT,"0.0.0.0", () => {
      logger.info(`🚀 Server running on port ${PORT} [${config.app.nodeEnv}]`);
      logger.info(`🔐 JWT Algorithm: ${config.jwt.algorithm}`);
      logger.info(`🔑 Password Hashing: Argon2id`);
      logger.info(`🔒 AES Encryption: ${config.encryption.algorithm} (key v${config.encryption.activeKeyVersion})`);
    });

    process.on('SIGTERM', () => shutdown('SIGTERM', server));
    process.on('SIGINT', () => shutdown('SIGINT', server));

    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled Rejection:', reason);
      shutdown('unhandledRejection', server);
    });

    process.on('uncaughtException', (err) => {
      logger.error('Uncaught Exception:', {
        message: err.message,
        stack: err.stack,
      });
      process.exit(1);
    });

  } catch (err) {
    logger.error('❌ Database connection failed', {
      message: err.message,
      stack: err.stack,
    });
    process.exit(1);
  }
};

startServer();