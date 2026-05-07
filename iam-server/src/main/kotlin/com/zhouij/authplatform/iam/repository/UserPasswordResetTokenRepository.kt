package com.zhouij.authplatform.iam.repository

import com.zhouij.authplatform.iam.domain.UserPasswordResetTokenEntity
import org.springframework.data.jpa.repository.JpaRepository

interface UserPasswordResetTokenRepository : JpaRepository<UserPasswordResetTokenEntity, Long> {
    fun findByJti(jti: String): UserPasswordResetTokenEntity?
}
