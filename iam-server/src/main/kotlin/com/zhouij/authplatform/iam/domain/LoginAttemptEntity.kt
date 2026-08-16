package com.zhouij.authplatform.iam.domain

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "login_attempts")
class LoginAttemptEntity(
    @Id
    @Column(nullable = false, length = 255)
    val email: String,

    @Column(name = "failed_count", nullable = false)
    var failedCount: Int = 0,

    @Column(name = "first_failed_at")
    var firstFailedAt: Instant? = null,

    @Column(name = "last_failed_at")
    var lastFailedAt: Instant? = null,

    @Column(name = "locked_until")
    var lockedUntil: Instant? = null
)
