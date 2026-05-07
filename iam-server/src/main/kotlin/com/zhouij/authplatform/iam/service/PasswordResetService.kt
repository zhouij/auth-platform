package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.domain.AdminPasswordResetTokenEntity
import com.zhouij.authplatform.iam.domain.UserPasswordResetTokenEntity
import com.zhouij.authplatform.iam.repository.AdminPasswordResetTokenRepository
import com.zhouij.authplatform.iam.repository.AdminUserRepository
import com.zhouij.authplatform.iam.repository.UserPasswordResetTokenRepository
import com.zhouij.authplatform.iam.repository.UserRepository
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import java.util.UUID
import javax.crypto.SecretKey

@Service
class PasswordResetService(
    private val userRepository: UserRepository,
    private val adminUserRepository: AdminUserRepository,
    private val userPasswordResetTokenRepository: UserPasswordResetTokenRepository,
    private val adminPasswordResetTokenRepository: AdminPasswordResetTokenRepository,
    private val passwordService: PasswordService
) {
    private val logger = LoggerFactory.getLogger(PasswordResetService::class.java)

    @Value("\${email.reset-link-base:http://localhost:3000/reset-password}")
    private lateinit var resetLinkBase: String

    @Value("\${email.enabled:false}")
    private var emailEnabled: Boolean = false

    // Ephemeral signing key for reset tokens — in production, load from a persisted key
    private val signingKey: SecretKey by lazy {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(256)
        val pair = gen.generateKeyPair()
        // Use the private key bytes for HMAC (simplified; prod should use persisted RSA/EC key)
        Keys.hmacShaKeyFor(pair.private.encoded.copyOf(32))
    }

    data class ResetTokenClaims(
        val sub: String,
        val userType: String,
        val jti: String,
        val purpose: String = "password-reset"
    )

    @Transactional
    fun requestReset(email: String, userType: String) {
        when (userType.uppercase()) {
            "USER" -> {
                val user = userRepository.findByEmailIgnoreCase(email).orElse(null) ?: return
                if (!user.enabled) return
                val token = createResetToken(user.id.toString(), "USER")
                userPasswordResetTokenRepository.save(
                    UserPasswordResetTokenEntity(
                        userId = user.id!!,
                        jti = token.jti,
                        expiresAt = Instant.now().plus(15, ChronoUnit.MINUTES)
                    )
                )
                sendResetEmail(email, token)
            }
            "ADMIN" -> {
                val admin = adminUserRepository.findByEmailIgnoreCase(email).orElse(null) ?: return
                if (!admin.enabled) return
                val token = createResetToken(admin.id.toString(), "ADMIN")
                adminPasswordResetTokenRepository.save(
                    AdminPasswordResetTokenEntity(
                        adminUserId = admin.id!!,
                        jti = token.jti,
                        expiresAt = Instant.now().plus(15, ChronoUnit.MINUTES)
                    )
                )
                sendResetEmail(email, token)
            }
        }
    }

    @Transactional
    fun completeReset(resetToken: String, newPassword: String): ResetResult {
        val claims = verifyResetToken(resetToken) ?: return ResetResult.INVALID_TOKEN
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
                user.passwordHash = passwordService.hashUser(newPassword)
                user.credentialsChangedAt = Instant.now()
                user.updatedAt = Instant.now()
                userRepository.save(user)

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
                admin.passwordHash = passwordService.hashAdmin(newPassword)
                admin.credentialsChangedAt = Instant.now()
                admin.updatedAt = Instant.now()
                adminUserRepository.save(admin)

                tokenEntity.used = true
                adminPasswordResetTokenRepository.save(tokenEntity)
                ResetResult.SUCCESS
            }
            else -> ResetResult.INVALID_TOKEN
        }
    }

    private fun createResetToken(sub: String, userType: String): ResetTokenClaims {
        val jti = UUID.randomUUID().toString()
        return ResetTokenClaims(sub = sub, userType = userType, jti = jti)
    }

    private fun verifyResetToken(token: String): ResetTokenClaims? {
        return try {
            val claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .payload

            val purpose = claims["purpose"] as? String ?: return null
            if (purpose != "password-reset") return null

            val exp = claims.expiration?.toInstant() ?: return null
            if (exp.isBefore(Instant.now())) return null

            ResetTokenClaims(
                sub = claims.subject,
                userType = claims["user_type"] as? String ?: return null,
                jti = claims["jti"] as? String ?: return null,
                purpose = purpose
            )
        } catch (e: Exception) {
            logger.debug("Reset token verification failed: {}", e.message)
            null
        }
    }

    private fun sendResetEmail(email: String, claims: ResetTokenClaims) {
        val signedToken = generateSignedToken(claims)
        val resetLink = "$resetLinkBase?token=$signedToken"
        if (emailEnabled) {
            logger.info("Password reset email to {} ({}) — link: {}", email, claims.userType, resetLink)
        } else {
            logger.info("PASSWORD RESET [{}]: {}", claims.userType, resetLink)
        }
    }

    fun generateSignedToken(claims: ResetTokenClaims): String {
        return Jwts.builder()
            .subject(claims.sub)
            .claim("user_type", claims.userType)
            .claim("jti", claims.jti)
            .claim("purpose", claims.purpose)
            .issuedAt(Date())
            .expiration(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
            .signWith(signingKey)
            .compact()
    }

    enum class ResetResult {
        SUCCESS, INVALID_TOKEN, TOKEN_USED, TOKEN_EXPIRED, WEAK_PASSWORD
    }
}
