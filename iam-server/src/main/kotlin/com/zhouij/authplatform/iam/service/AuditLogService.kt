package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.domain.AuditLogEntity
import com.zhouij.authplatform.iam.repository.AuditLogRepository
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Propagation
import org.springframework.transaction.annotation.Transactional

/**
 * Append-only security audit trail for authentication events and
 * administrative actions. Failure events are written in a REQUIRES_NEW
 * transaction so they survive rollbacks of the calling transaction.
 */
@Service
class AuditLogService(
    private val auditLogRepository: AuditLogRepository
) {
    private val logger = LoggerFactory.getLogger(AuditLogService::class.java)

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    fun record(
        action: String,
        outcome: AuditLogEntity.Outcome,
        actorType: String? = null,
        actorId: String? = null,
        target: String? = null,
        ipAddress: String? = null,
        detail: String? = null
    ) {
        try {
            auditLogRepository.save(
                AuditLogEntity(
                    actorType = actorType,
                    actorId = actorId,
                    action = action,
                    target = target,
                    ipAddress = ipAddress,
                    outcome = outcome.name,
                    detail = detail
                )
            )
        } catch (e: Exception) {
            // Auditing must never break the primary flow
            logger.error("Failed to write audit log entry (action={}, outcome={})", action, outcome, e)
        }
    }
}
