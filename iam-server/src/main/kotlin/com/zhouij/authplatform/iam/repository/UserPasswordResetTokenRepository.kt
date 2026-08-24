package com.zhouij.authplatform.iam.repository

import com.zhouij.authplatform.iam.domain.UserPasswordResetTokenEntity
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

interface UserPasswordResetTokenRepository : JpaRepository<UserPasswordResetTokenEntity, Long> {
    fun findByJti(jti: String): UserPasswordResetTokenEntity?

    @Modifying
    @Transactional
    fun deleteByUserId(userId: UUID)
}
