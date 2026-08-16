package com.zhouij.authplatform.iam.domain

import jakarta.persistence.*
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "password_history")
class PasswordHistoryEntity(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = null,

    @Column(name = "user_id")
    val userId: UUID? = null,

    @Column(name = "admin_user_id")
    val adminUserId: UUID? = null,

    @Column(name = "password_hash", nullable = false, length = 512)
    val passwordHash: String,

    @Column(name = "created_at", nullable = false, updatable = false)
    val createdAt: Instant = Instant.now()
)
