import Redis from 'ioredis';
import { PrismaClient } from '@prisma/client';
import winston from 'winston';

const prisma = new PrismaClient();
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console()
  ]
});

// Redis client setup for the worker
const redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

redisClient.on('error', (err) => logger.error('Redis Worker Error:', err.message));

const STREAM_KEY = 'security_events';
const GROUP_NAME = 'audit_workers';
const CONSUMER_NAME = `worker_${process.pid}`;

async function initializeRedis() {
  try {
    // Create consumer group, $ means only process new messages that arrive after creation
    // MKSTREAM automatically creates the stream if it doesn't exist
    await redisClient.xgroup('CREATE', STREAM_KEY, GROUP_NAME, '$', 'MKSTREAM');
    logger.info(`Created Redis consumer group: ${GROUP_NAME}`);
  } catch (err) {
    if (err.message.includes('BUSYGROUP')) {
      logger.info(`Consumer group ${GROUP_NAME} already exists.`);
    } else {
      throw err;
    }
  }
}

async function saveToPostgres(eventData) {
  try {
    await prisma.auditLog.create({
      data: {
        userId: eventData.user_id && eventData.user_id !== 'SYSTEM' ? eventData.user_id : undefined,
        action: eventData.action || 'UNKNOWN',
        status: eventData.result || 'SUCCESS',
        ip: eventData.source_ip || 'unknown',
        userAgent: eventData.user_agent || 'unknown',
        metadata: eventData, // Store the full graph event in JSON metadata
      },
    });
  } catch (err) {
    logger.error('PostgreSQL Insert Failed', { error: err.message, eventId: eventData.event_id });
    throw err; // Re-throw to prevent ACK and enable retry
  }
}

async function saveToNeo4j(eventData) {
  // Currently, Neo4j parsing happens via an external log scraping script (neo4j_ingest.js).
  // By logging the exact format, we maintain compatibility.
  // In a future direct-driver implementation, actual Neo4j queries would go here.
  logger.info('GRAPH_EVENT', eventData);
}

async function processStream() {
  logger.info(`Worker ${CONSUMER_NAME} started listening to stream: ${STREAM_KEY}`);

  while (true) {
    try {
      // 1. Read from stream, blocking for up to 5000ms. 
      // '>' means: read messages never delivered to other consumers in this group.
      const response = await redisClient.xreadgroup(
        'GROUP', GROUP_NAME, CONSUMER_NAME,
        'COUNT', 50,
        'BLOCK', 5000,
        'STREAMS', STREAM_KEY, '>'
      );

      if (response && response.length > 0) {
        const streamData = response[0]; // [streamName, messagesArray]
        const messages = streamData[1];

        if (messages.length > 0) {
          logger.info(`Worker picked up ${messages.length} events from stream.`);
        }

        for (const message of messages) {
          try {
            const messageId = message[0];
            const keyValues = message[1]; // ['data', '{"event_id":...}']
            
            // Extract JSON from key-value pairs
            let rawData = null;
            for (let i = 0; i < keyValues.length; i += 2) {
              if (keyValues[i] === 'data') {
                rawData = keyValues[i + 1];
                break;
              }
            }

            if (!rawData) continue;

            const eventData = JSON.parse(rawData);

            // 2. Perform DB logic
            await Promise.all([
              saveToPostgres(eventData),
              saveToNeo4j(eventData)
            ]);

            // 3. Acknowledge successful processing so it's removed from pending
            await redisClient.xack(STREAM_KEY, GROUP_NAME, messageId);
          } catch (eventErr) {
            logger.error(`Failed to process event ${message[0]}`, { error: eventErr.message });
            // By NOT acking, the message remains in the Pending Entries List (PEL).
            // A separate Dead Letter process can use XPENDING / XCLAIM to retry.
          }
        }
      }
    } catch (err) {
      logger.error('Stream processing loop error', { error: err.message });
      await new Promise(res => setTimeout(res, 2000)); // Sleep before resuming to avoid CPU spiral
    }
  }
}

// Global top-level async execution
(async () => {
  try {
    await initializeRedis();
    await processStream();
  } catch (err) {
    logger.error('Fatally crashed worker', { error: err.message });
    process.exit(1);
  }
})();
