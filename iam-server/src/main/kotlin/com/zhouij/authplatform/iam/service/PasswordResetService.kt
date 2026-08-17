package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.domain.AdminPasswordResetTokenEntity
import com.zhouij.authplatform.iam.domain.UserPasswordResetTokenEntity
import com.zhouij.authplatform.iam.repository.AdminPasswordResetTokenRepository
import com.zhouij.authplatform.iam.repository.AdminUserRepository
import com.zhouij.authplatform.iam.repository.UserPasswordResetTokenRepository
import com.zhouij.authplatform.iam.repository.UserRepository
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

@Service
class PasswordResetService(
    private val userRepository: UserRepository,
    private val adminUserRepository: AdminUserRepository,
    private val userPasswordResetTokenRepository: UserPasswordResetTokenRepository,
    private val adminPasswordResetTokenRepository: AdminPasswordResetTokenRepository,
    private val passwordService: PasswordService,
    private val passwordHistoryService: PasswordHistoryService,
    private val iamTokenService: IamTokenService,
    private val emailService: EmailService
) {
    private val logger = LoggerFactory.getLogger(PasswordResetService::class.java)

    @Value("\${email.reset-link-base:http://localhost:3000/reset-password}")
    private lateinit var resetLinkBase: String

    companion object {
        const val RESET_TOKEN_TTL_MINUTES = 15L
    }

    @Transactional
    fun requestReset(email: String, userType: String) {
        when (userType.uppercase()) {
            "USER" -> {
                val user = userRepository.findByEmailIgnoreCase(email).orElse(null) ?: return
                if (!user.enabled) return
                val (signedToken, claims) = iamTokenService.createToken(
                    sub = user.id.toString(),
                    userType = "USER",
                    purpose = "password-reset",
                    ttlMinutes = RESET_TOKEN_TTL_MINUTES
                )
                userPasswordResetTokenRepository.save(
                    UserPasswordResetTokenEntity(
                        userId = user.id!!,
                        jti = claims.jti,
                        expiresAt = Instant.now().plus(RESET_TOKEN_TTL_MINUTES, ChronoUnit.MINUTES)
                    )
                )
                emailService.sendPasswordReset(email, "USER", "$resetLinkBase?token=$signedToken")
            }
            "ADMIN" -> {
                val admin = adminUserRepository.findByEmailIgnoreCase(email).orElse(null) ?: return
                if (!admin.enabled) return
                val (signedToken, claims) = iamTokenService.createToken(
                    sub = admin.id.toString(),
                    userType = "ADMIN",
                    purpose = "password-reset",
                    ttlMinutes = RESET_TOKEN_TTL_MINUTES
                )
                adminPasswordResetTokenRepository.save(
                    AdminPasswordResetTokenEntity(
                        adminUserId = admin.id!!,
                        jti = claims.jti,
                        expiresAt = Instant.now().plus(RESET_TOKEN_TTL_MINUTES, ChronoUnit.MINUTES)
                    )
                )
                emailService.sendPasswordReset(email, "ADMIN", "$resetLinkBase?token=$signedToken")
            }
        }
    }

    @Transactional
    fun completeReset(resetToken: String, newPassword: String): ResetResult {
        val claims = iamTokenService.verifyToken(resetToken, "password-reset")
            ?: return ResetResult.INVALID_TOKEN
        val userId = UUID.fromString(claims.sub)

        return when (claims.userType.uppercase()) {
            "USER" -> {
                val tokenEntity = userPasswordResetTokenRepository.findByJti(claims.jti)
                    ?: return ResetResult.INVALID_TOKEN
                if (tokenEntity.used) return ResetResult.TOKEN_USED
                if (tokenEntity.expiresAt.isBefore(Instant.now())) return ResetResult.TOKEN_EXPIRED

                val user = userRepository.findById(userId).orElse(null) ?: return ResetResult.INVALID_TOKEN
                if (!user.enabled) return ResetResult.INVALID_TOKEN
                if (!passwordService.validatePasswordStrength(newPassword)) return ResetResult.WEAK_PASSWORD
                if (passwordHistoryService.wasUsedRecently(userId = userId, adminUserId = null, newPassword)) {
                    return ResetResult.PASSWORD_REUSED
                }
                user.passwordHash = passwordService.hashUser(newPassword)
                user.credentialsChangedAt = Instant.now()
                user.updatedAt = Instant.now()
                userRepository.save(user)
                passwordHistoryService.record(userId = userId, adminUserId = null, passwordHash = user.passwordHash)

                tokenEntity.used = true
                userPasswordResetTokenRepository.save(tokenEntity)
                ResetResult.SUCCESS
            }
            "ADMIN" -> {
                val tokenEntity = adminPasswordResetTokenRepository.findByJti(claims.jti)
                    ?: return ResetResult.INVALID_TOKEN
                if (tokenEntity.used) return ResetResult.TOKEN_USED
                if (tokenEntity.expiresAt.isBefore(Instant.now())) return ResetResult.TOKEN_EXPIRED

                val admin = adminUserRepository.findById(userId).orElse(null) ?: return ResetResult.INVALID_TOKEN
                if (!admin.enabled) return ResetResult.INVALID_TOKEN
                if (!passwordService.validateAdminPasswordStrength(newPassword)) return ResetResult.WEAK_PASSWORD
                if (passwordHistoryService.wasUsedRecently(userId = null, adminUserId = userId, newPassword)) {
                    return ResetResult.PASSWORD_REUSED
                }
                admin.passwordHash = passwordService.hashAdmin(newPassword)
                admin.credentialsChangedAt = Instant.now()
                admin.updatedAt = Instant.now()
                adminUserRepository.save(admin)
                passwordHistoryService.record(userId = null, adminUserId = userId, passwordHash = admin.passwordHash)

                tokenEntity.used = true
                adminPasswordResetTokenRepository.save(tokenEntity)
                ResetResult.SUCCESS
            }
            else -> ResetResult.INVALID_TOKEN
        }
    }

    enum class ResetResult {
        SUCCESS, INVALID_TOKEN, TOKEN_USED, TOKEN_EXPIRED, WEAK_PASSWORD, PASSWORD_REUSED
    }
}
