package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.domain.LoginAttemptEntity
import com.zhouij.authplatform.iam.repository.LoginAttemptRepository
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Duration
import java.time.Instant

/**
 * Brute-force protection for credential checks: counts consecutive failed
 * attempts per account (email) within a sliding window and locks the account
 * out for a configurable duration once the threshold is crossed.
 *
 * Lockout state is persisted, so it survives restarts and applies to both the
 * public login endpoint and the internal (auth-server) credential validation.
 */
@Service
class LoginAttemptService(
    private val loginAttemptRepository: LoginAttemptRepository
) {
    private val logger = LoggerFactory.getLogger(LoginAttemptService::class.java)

    @Value("\${iam.login.max-attempts:5}")
    private var maxAttempts: Int = 5

    @Value("\${iam.login.lockout-minutes:15}")
    private var lockoutMinutes: Long = 15

    @Value("\${iam.login.window-minutes:15}")
    private var windowMinutes: Long = 15

    /** Remaining lockout duration, or null when the account is not locked. */
    @Transactional(readOnly = true)
    fun lockoutRemaining(email: String): Duration? {
        val entry = loginAttemptRepository.findById(email.lowercase()).orElse(null) ?: return null
        val lockedUntil = entry.lockedUntil ?: return null
        val remaining = Duration.between(Instant.now(), lockedUntil)
        if (remaining.isNegative || remaining.isZero) {
            // Lock expired — clear it lazily
            loginAttemptRepository.delete(entry)
            return null
        }
        return remaining
    }

    @Transactional
    fun recordFailure(email: String) {
        val normalized = email.lowercase()
        val now = Instant.now()
        val entry = loginAttemptRepository.findById(normalized).orElse(null)

        val windowStart = now.minusSeconds(windowMinutes * 60)
        val base = if (entry == null || entry.firstFailedAt == null || entry.firstFailedAt!!.isBefore(windowStart)) {
            LoginAttemptEntity(email = normalized)
        } else {
            entry
        }

        if (entry != null && entry !== base) {
            loginAttemptRepository.delete(entry)
        }

        base.failedCount = if (base.firstFailedAt == null || base.firstFailedAt!!.isBefore(windowStart)) {
            1
        } else {
            base.failedCount + 1
        }
        base.firstFailedAt = if (base.firstFailedAt == null || base.firstFailedAt!!.isBefore(windowStart)) {
            now
        } else {
            base.firstFailedAt
        }
        base.lastFailedAt = now

        if (base.failedCount >= maxAttempts) {
            base.lockedUntil = now.plusSeconds(lockoutMinutes * 60)
            logger.warn(
                "Account {} locked for {} minutes after {} failed login attempts",
                normalized, lockoutMinutes, base.failedCount
            )
        }
        loginAttemptRepository.save(base)
    }

    @Transactional
    fun recordSuccess(email: String) {
        loginAttemptRepository.deleteById(email.lowercase())
    }
}
