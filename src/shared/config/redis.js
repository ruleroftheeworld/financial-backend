import Redis from 'ioredis';
import logger from '../utils/logger.js';
import { redis as redisConfig } from './index.js';

const redisClient = new Redis(redisConfig.url);

redisClient.on('connect', () => {
  logger.info('Connected to Redis successfully');
});

redisClient.on('error', (err) => {
  logger.error('Redis Connection Error', { error: err.message });
});

export default redisClient;
