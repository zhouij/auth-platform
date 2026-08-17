package com.zhouij.authplatform.iam.repository

import com.zhouij.authplatform.iam.domain.AdminPasswordResetTokenEntity
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

interface AdminPasswordResetTokenRepository : JpaRepository<AdminPasswordResetTokenEntity, Long> {
    fun findByJti(jti: String): AdminPasswordResetTokenEntity?

    @Modifying
    @Transactional
    fun deleteByAdminUserId(adminUserId: UUID)
}
