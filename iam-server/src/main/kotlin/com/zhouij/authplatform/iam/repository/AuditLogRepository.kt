package com.zhouij.authplatform.iam.repository

import com.zhouij.authplatform.iam.domain.AuditLogEntity
import org.springframework.data.jpa.repository.JpaRepository

interface AuditLogRepository : JpaRepository<AuditLogEntity, Long>
