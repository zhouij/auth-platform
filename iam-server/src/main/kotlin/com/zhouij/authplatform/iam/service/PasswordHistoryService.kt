package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.domain.PasswordHistoryEntity
import com.zhouij.authplatform.iam.repository.PasswordHistoryRepository
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.data.domain.PageRequest
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

/**
 * Enforces a bounded password history: new passwords must not match any of the
 * account's N most recent hashes, and old entries are trimmed automatically.
 */
@Service
class PasswordHistoryService(
    private val passwordHistoryRepository: PasswordHistoryRepository,
    private val passwordService: PasswordService
) {
    private val logger = LoggerFactory.getLogger(PasswordHistoryService::class.java)

    @Value("\${iam.password.history-size:5}")
    private var historySize: Int = 5

    @Transactional
    fun wasUsedRecently(userId: UUID?, adminUserId: UUID?, newPassword: String): Boolean {
        val recent = recentHashes(userId, adminUserId)
        return recent.any { encoded ->
            val matches = when {
                userId != null -> passwordService.matchesUser(newPassword, encoded)
                else -> passwordService.matchesAdmin(newPassword, encoded)
            }
            if (matches) {
                logger.warn("Rejected password change: new password matches a recent password in history")
            }
            matches
        }
    }

    @Transactional
    fun record(userId: UUID?, adminUserId: UUID?, passwordHash: String) {
        require((userId == null) != (adminUserId == null)) {
            "Exactly one of userId/adminUserId must be set"
        }
        passwordHistoryRepository.save(
            PasswordHistoryEntity(userId = userId, adminUserId = adminUserId, passwordHash = passwordHash)
        )
        trim(userId, adminUserId)
    }

    /** Erasure support: drop the account's password history. */
    @Transactional
    fun deleteHistoryForUser(userId: UUID) = passwordHistoryRepository.deleteByUserId(userId)

    /** Erasure support: drop the admin account's password history. */
    @Transactional
    fun deleteHistoryForAdmin(adminUserId: UUID) = passwordHistoryRepository.deleteByAdminUserId(adminUserId)

    private fun recentHashes(userId: UUID?, adminUserId: UUID?): List<String> {
        val page = PageRequest.of(0, historySize.coerceAtLeast(1))
        return when {
            userId != null -> passwordHistoryRepository.findRecentForUser(userId, page)
            else -> passwordHistoryRepository.findRecentForAdmin(adminUserId!!, page)
        }.map { it.passwordHash }
    }

    private fun trim(userId: UUID?, adminUserId: UUID?) {
        // The table is trimmed on every record(), so it can hold at most
        // historySize+1 rows; fetch a bounded page and delete the overflow.
        val page = PageRequest.of(0, historySize.coerceAtLeast(1) + 100)
        val overflow = when {
            userId != null -> passwordHistoryRepository.findRecentForUser(userId, page)
            else -> passwordHistoryRepository.findRecentForAdmin(adminUserId!!, page)
        }
        if (overflow.size > historySize) {
            passwordHistoryRepository.deleteAll(overflow.drop(historySize))
        }
    }
}
