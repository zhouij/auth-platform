package com.zhouij.authplatform.authserver.controller

import com.nimbusds.jwt.SignedJWT
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.ResponseEntity
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
import java.time.Instant

@RestController
@RequestMapping("/internal")
class InternalController(
    private val jdbcTemplate: JdbcTemplate
) {
    private val logger = LoggerFactory.getLogger(InternalController::class.java)

    @Value("\${iam.internal-token:dev-internal-token}")
    private lateinit var internalToken: String

    /**
     * Revokes every stored authorization for a user: issued access tokens are
     * added to the denylist (keyed by their jti, until expiry) so enforcement
     * points can reject them immediately, and the authorization rows (which
     * back refresh tokens) are deleted.
     */
    @PostMapping("/auth/revoke-user/{userId}")
    fun revokeUserTokens(
        @RequestHeader("X-Internal-Token") token: String,
        @PathVariable userId: String
    ): ResponseEntity<Map<String, String>> {
        if (token != internalToken) return ResponseEntity.status(401).build()

        val accessTokens = jdbcTemplate.queryForList(
            "SELECT access_token_value FROM oauth2_authorization WHERE principal_name = ? AND access_token_value IS NOT NULL",
            String::class.java,
            userId
        )

        var denylisted = 0
        accessTokens.forEach { jwt ->
            try {
                val signed = SignedJWT.parse(jwt)
                val jti = signed.jwtClaimsSet.getJWTID()
                val exp = signed.jwtClaimsSet.expirationTime?.toInstant()
                if (jti != null && exp != null && exp.isAfter(Instant.now())) {
                    jdbcTemplate.update(
                        "INSERT INTO oauth2_token_denylist (jti, expires_at) VALUES (?, ?) ON CONFLICT (jti) DO NOTHING",
                        jti,
                        java.sql.Timestamp.from(exp)
                    )
                    denylisted++
                }
            } catch (e: Exception) {
                logger.warn("Could not denylist an issued token during revocation: {}", e.message)
            }
        }

        // Delete all refresh tokens and authorizations for this user
        val deletedAuths = jdbcTemplate.update(
            "DELETE FROM oauth2_authorization WHERE principal_name = ?",
            userId
        )
        cleanupExpiredDenylistEntries()

        logger.info(
            "Revoked {} authorization(s) and denylisted {} access token(s) for user {}",
            deletedAuths, denylisted, userId
        )

        return ResponseEntity.ok(
            mapOf(
                "message" to "Tokens revoked",
                "revokedCount" to deletedAuths.toString(),
                "denylistedTokens" to denylisted.toString()
            )
        )
    }

    /**
     * Internal revocation lookup for enforcement points (gateway): is this
     * token id on the denylist? Cached per-request on the gateway side.
     */
    @GetMapping("/tokens/revoked/{jti}")
    fun isTokenRevoked(
        @RequestHeader("X-Internal-Token") token: String,
        @PathVariable jti: String
    ): ResponseEntity<Map<String, Boolean>> {
        if (token != internalToken) return ResponseEntity.status(401).build()

        val count = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM oauth2_token_denylist WHERE jti = ? AND expires_at > now()",
            Integer::class.java,
            jti
        ) ?: 0
        return ResponseEntity.ok(mapOf("revoked" to (count > 0)))
    }

    private fun cleanupExpiredDenylistEntries() {
        jdbcTemplate.update("DELETE FROM oauth2_token_denylist WHERE expires_at <= now()")
    }
}
