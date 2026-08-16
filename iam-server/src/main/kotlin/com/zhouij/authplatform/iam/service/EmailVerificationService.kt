package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.domain.UserEntity
import com.zhouij.authplatform.iam.repository.UserRepository
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

/**
 * Email verification for end-user accounts. The verification link carries a
 * self-contained signed token (24h TTL), so no extra storage is required.
 */
@Service
class EmailVerificationService(
    private val userRepository: UserRepository,
    private val iamTokenService: IamTokenService,
    private val emailService: EmailService
) {
    @Value("\${email.verification-link-base:http://localhost:3000/verify-email}")
    private lateinit var verificationLinkBase: String

    companion object {
        const val VERIFICATION_TOKEN_TTL_MINUTES = 24 * 60L
    }

    fun sendVerificationEmail(user: UserEntity) {
        if (user.emailVerified) return
        val (signedToken, _) = iamTokenService.createToken(
            sub = user.id.toString(),
            userType = "USER",
            purpose = "email-verification",
            ttlMinutes = VERIFICATION_TOKEN_TTL_MINUTES
        )
        emailService.sendVerification(user.email, "$verificationLinkBase?token=$signedToken")
    }

    /** Returns true when the token was valid and the account is now verified. */
    @Transactional
    fun verify(token: String): Boolean {
        val claims = iamTokenService.verifyToken(token, "email-verification") ?: return false
        val userId = runCatching { UUID.fromString(claims.sub) }.getOrNull() ?: return false
        val user = userRepository.findById(userId).orElse(null) ?: return false
        if (!user.enabled) return false
        user.emailVerified = true
        user.updatedAt = java.time.Instant.now()
        userRepository.save(user)
        return true
    }
}
