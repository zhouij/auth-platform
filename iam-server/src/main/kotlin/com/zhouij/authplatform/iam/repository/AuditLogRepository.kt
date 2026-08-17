package com.zhouij.authplatform.iam.repository

import com.zhouij.authplatform.iam.domain.AuditLogEntity
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

interface AuditLogRepository : JpaRepository<AuditLogEntity, Long> {

    @Modifying
    @Transactional
    fun deleteByOccurredAtBefore(cutoff: Instant): Int
}
