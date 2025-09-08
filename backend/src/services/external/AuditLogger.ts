import { logger } from '@root/utils/logger';

/**
 * Defines the structure for an audit log entry.
 */
export interface AuditLogEntry {
  timestamp: Date;
  actorId?: string; // e.g., userId, eID session ID, or service account ID
  eventType: string; // e.g., 'EID_AUTHENTICATION_SUCCESS', 'USER_LOGIN_FAILURE', 'ATTRIBUTE_RELEASE'
  resource?: string; // e.g., '/api/v1/eid/auth', 'User:123', 'Attributes:GivenName'
  description?: string; // A detailed description of the event
  outcome: 'SUCCESS' | 'FAILURE' | 'INFO';
  ipAddress?: string;
  userAgent?: string;
  details?: Record<string, any>; // Additional relevant data
}

/**
 * Service for handling audit logging.
 * This service ensures that critical events are logged for security, compliance,
 * and troubleshooting purposes.
 */
export class AuditLogger {
  /**
   * Logs an audit event.
   * @param entry The audit log entry to record.
   */
  public log(entry: AuditLogEntry): void {
    const logMessage = {
      ...entry,
      timestamp: entry.timestamp.toISOString(), // Ensure consistent timestamp format
    };

    switch (entry.outcome) {
      case 'SUCCESS':
        logger.info('AUDIT_SUCCESS', logMessage);
        break;
      case 'FAILURE':
        logger.error('AUDIT_FAILURE', logMessage);
        break;
      case 'INFO':
      default:
        logger.info('AUDIT_INFO', logMessage);
        break;
    }
  }

  /**
   * Logs a successful audit event.
   * @param eventType The type of event (e.g., 'EID_AUTHENTICATION_SUCCESS').
   * @param actorId The ID of the actor (user, session, etc.).
   * @param resource The resource affected by the event.
   * @param description A description of the event.
   * @param details Additional details for the log.
   */
  public logSuccess(eventType: string, actorId?: string, resource?: string, description?: string, ipAddress?: string, userAgent?: string, details?: Record<string, any>): void {
    this.log({
      timestamp: new Date(),
      actorId,
      eventType,
      resource,
      description,
      outcome: 'SUCCESS',
      ipAddress,
      userAgent,
      details,
    });
  }

  /**
   * Logs a failed audit event.
   * @param eventType The type of event (e.g., 'USER_LOGIN_FAILURE').
   * @param actorId The ID of the actor (user, session, etc.).
   * @param resource The resource affected by the event.
   * @param description A description of the failure.
   * @param details Additional details for the log.
   */
  public logFailure(eventType: string, actorId?: string, resource?: string, description?: string, ipAddress?: string, userAgent?: string, details?: Record<string, any>): void {
    this.log({
      timestamp: new Date(),
      actorId,
      eventType,
      resource,
      description,
      outcome: 'FAILURE',
      ipAddress,
      userAgent,
      details,
    });
  }

  /**
   * Logs an informational audit event.
   * @param eventType The type of event (e.g., 'EID_SESSION_CREATED').
   * @param actorId The ID of the actor (user, session, etc.).
   * @param resource The resource affected by the event.
   * @param description A description of the event.
   * @param details Additional details for the log.
   */
  public logInfo(eventType: string, actorId?: string, resource?: string, description?: string, ipAddress?: string, userAgent?: string, details?: Record<string, any>): void {
    this.log({
      timestamp: new Date(),
      actorId,
      eventType,
      resource,
      description,
      outcome: 'INFO',
      ipAddress,
      userAgent,
      details,
    });
  }
}

// Export a singleton instance for easier use throughout the application
export const auditLogger = new AuditLogger();