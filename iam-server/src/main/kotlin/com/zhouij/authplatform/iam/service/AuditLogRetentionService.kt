package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.repository.AuditLogRepository
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import java.time.Instant

/**
 * Bounded audit-log retention: prunes entries older than
 * `iam.audit.retention-days` (default 90; 0 disables pruning) on the
 * configured cron (`iam.audit.retention-cron`, default daily at 04:00).
 */
@Service
class AuditLogRetentionService(
    private val auditLogRepository: AuditLogRepository
) {
    private val logger = LoggerFactory.getLogger(AuditLogRetentionService::class.java)

    @Value("\${iam.audit.retention-days:90}")
    private var retentionDays: Int = 90

    @Scheduled(cron = "\${iam.audit.retention-cron:0 0 4 * * *}")
    fun pruneExpiredEntries() {
        if (retentionDays <= 0) return
        val cutoff = Instant.now().minusSeconds(retentionDays * 24L * 3600L)
        val deleted = auditLogRepository.deleteByOccurredAtBefore(cutoff)
        if (deleted > 0) {
            logger.info("Audit-log retention: pruned {} entr(ies) older than {} days", deleted, retentionDays)
        }
    }
}
