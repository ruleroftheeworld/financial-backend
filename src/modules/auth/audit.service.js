import prisma from '../../shared/config/database.js';
import logger from '../../shared/utils/logger.js';
import crypto from 'crypto';
import { recordStrike } from '../../shared/middleware/activeDefender.js';
import redisClient from '../../shared/config/redis.js';

// ─────────────────────────────────────────────
// SEVERITY MAPPING: status → defense severity
// ─────────────────────────────────────────────
const SEVERITY_MAP = {
  FAILURE: 'HIGH',
  MFA_FAILED: 'HIGH',
  SUSPICIOUS_SESSION_DETECTED: 'CRITICAL',
  SESSION_COMPROMISED: 'CRITICAL',
  // Default failures
};

const inferSeverity = (status) => {
  return SEVERITY_MAP[status] || (status?.includes('FAIL') ? 'MEDIUM' : null);
};

export const logSecurityEvent = async (payload) => {
  // Normalize payload because activeDefender sends the raw flat object while auth.service sends { action, status, ip, metadata }
  const { userId, action, status, ip, userAgent, metadata, event_type, source_ip, ...restOfPayload } = payload;
  const resolvedIp = ip || source_ip;
  const resolvedStatus = status || payload.result || 'SUCCESS';
  const resolvedEventType = event_type || metadata?.event_type || 'SECURITY';

  const metaJson = metadata ? JSON.parse(JSON.stringify(metadata)) : {};
  const mergedMeta = { ...metaJson, ...restOfPayload, event_type: resolvedEventType };

  // 🛡️ ACTIVE DEFENSE: Record strike BEFORE database operations
  const severity = inferSeverity(resolvedStatus);
  if (severity && resolvedIp && resolvedEventType !== "DEFENSE") {
    // Only record strikes for non-defense events to avert recursion
    recordStrike(resolvedIp, severity, `${action}:${resolvedStatus}`).catch(() => {});
  }

  const isSimulated = userAgent?.includes('attack-engine') || resolvedIp?.startsWith('192.168.');
  
  // 🕸️ GRAPH_EVENT: Emit normalized event for Neo4j IMMEDIATELY
  const baseGraphEvent = {
      event_id: crypto.randomUUID(),
      correlation_id: mergedMeta?.correlation_id || crypto.randomUUID(),
      user_id: userId || 'SYSTEM',
      user_email: mergedMeta?.user_email || null,
      event_type: resolvedEventType,
      action,
      source_ip: resolvedIp || 'unknown',
      ip_type: isSimulated ? "SIMULATED" : "REAL",
      user_agent: userAgent || 'unknown',
      agent_type: isSimulated ? "SIMULATED" : "REAL",
      target_type: "API",
      target_endpoint: mergedMeta?.path || "internal",
      result: resolvedStatus,
      severity: payload.severity || mergedMeta?.severity || (resolvedStatus === 'FAILURE' ? 'MEDIUM' : 'LOW'),
      timestamp: payload.timestamp || mergedMeta?.timestamp || new Date().toISOString()
  };
  
  const graphEvent = { ...baseGraphEvent, ...mergedMeta };
  logger.info('GRAPH_EVENT', graphEvent);

  try {
    // Write normalized graphEvent to Async Redis Stream
    await redisClient.xadd(
      'security_events',
      '*',
      'data',
      JSON.stringify(graphEvent)
    );
    
    // Explicit confirmation for DEFENSE events (critical for pipeline debugging)
    if (resolvedEventType === 'DEFENSE') {
      logger.info('DEFENSE_EVENT_QUEUED', { action, source_ip: resolvedIp, status: resolvedStatus });
    }
  } catch (error) {
    logger.error('Failed to queue security event to Redis', {
      error: error.message,
      action,
      event_type: resolvedEventType,
      source_ip: resolvedIp,
    });
  }
};

