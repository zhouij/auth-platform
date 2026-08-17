package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.config.SigningKeyStore
import io.jsonwebtoken.Jwts
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import java.util.UUID

/**
 * Issues and verifies IAM self-contained tokens (password reset, email
 * verification). Signing key comes from [SigningKeyStore] (persisted), and
 * verification accepts both the current key and configured rotation keys.
 */
@Service
class IamTokenService(
    private val signingKeyStore: SigningKeyStore
) {
    private val logger = LoggerFactory.getLogger(IamTokenService::class.java)

    data class TokenClaims(
        val sub: String,
        val userType: String,
        val jti: String,
        val purpose: String
    )

    fun createToken(
        sub: String,
        userType: String,
        purpose: String,
        ttlMinutes: Long
    ): Pair<String, TokenClaims> {
        val claims = TokenClaims(
            sub = sub,
            userType = userType,
            jti = UUID.randomUUID().toString(),
            purpose = purpose
        )
        return generateSignedToken(claims, ttlMinutes) to claims
    }

    fun verifyToken(token: String, purpose: String): TokenClaims? {
        return try {
            // Try the current key first, then rotation keys — but don't trust
            // arbitrary-key results for token reuse; JJWT throws on mismatch.
            for (key in signingKeyStore.verificationKeys) {
                val claims = try {
                    Jwts.parser()
                        .verifyWith(key)
                        .build()
                        .parseSignedClaims(token)
                        .payload
                } catch (e: Exception) {
                    null // try next key
                } ?: continue

                val tokenPurpose = claims["purpose"] as? String ?: return null
                if (tokenPurpose != purpose) return null

                val exp = claims.expiration?.toInstant() ?: return null
                if (exp.isBefore(Instant.now())) return null

                return TokenClaims(
                    sub = claims.subject,
                    userType = claims["user_type"] as? String ?: return null,
                    jti = claims["jti"] as? String ?: return null,
                    purpose = tokenPurpose
                )
            }
            null
        } catch (e: Exception) {
            logger.debug("Token verification failed: {}", e.message)
            null
        }
    }

    private fun generateSignedToken(claims: TokenClaims, ttlMinutes: Long): String {
        return Jwts.builder()
            .subject(claims.sub)
            .claim("user_type", claims.userType)
            .claim("jti", claims.jti)
            .claim("purpose", claims.purpose)
            .issuedAt(Date())
            .expiration(Date.from(Instant.now().plus(ttlMinutes, ChronoUnit.MINUTES)))
            .signWith(signingKeyStore.signingKey())
            .compact()
    }
}
