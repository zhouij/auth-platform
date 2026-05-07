package com.zhouij.authplatform.iam.repository

import com.zhouij.authplatform.iam.domain.AdminPasswordResetTokenEntity
import org.springframework.data.jpa.repository.JpaRepository

interface AdminPasswordResetTokenRepository : JpaRepository<AdminPasswordResetTokenEntity, Long> {
    fun findByJti(jti: String): AdminPasswordResetTokenEntity?
}
