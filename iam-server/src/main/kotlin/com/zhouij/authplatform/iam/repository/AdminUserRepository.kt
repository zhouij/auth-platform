package com.zhouij.authplatform.iam.repository

import com.zhouij.authplatform.iam.domain.AdminUserEntity
import org.springframework.data.jpa.repository.JpaRepository
import java.util.Optional
import java.util.UUID

interface AdminUserRepository : JpaRepository<AdminUserEntity, UUID> {
    fun findByEmailIgnoreCase(email: String): Optional<AdminUserEntity>
    fun findByUsernameIgnoreCase(username: String): Optional<AdminUserEntity>
    fun existsByEmailIgnoreCase(email: String): Boolean
    fun existsByUsernameIgnoreCase(username: String): Boolean
}
