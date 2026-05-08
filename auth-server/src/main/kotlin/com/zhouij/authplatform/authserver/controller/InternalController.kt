package com.zhouij.authplatform.authserver.controller

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.ResponseEntity
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/internal")
class InternalController(
    private val jdbcTemplate: JdbcTemplate
) {
    private val logger = LoggerFactory.getLogger(InternalController::class.java)

    @Value("\${iam.internal-token:dev-internal-token}")
    private lateinit var internalToken: String

    @PostMapping("/auth/revoke-user/{userId}")
    fun revokeUserTokens(
        @RequestHeader("X-Internal-Token") token: String,
        @PathVariable userId: String
    ): ResponseEntity<Map<String, String>> {
        if (token != internalToken) return ResponseEntity.status(401).build()

        // Revoke all refresh tokens and authorizations for this user
        val deletedAuths = jdbcTemplate.update(
            "DELETE FROM oauth2_authorization WHERE principal_name = ?",
            userId
        )
        logger.info("Revoked {} authorizations for user {}", deletedAuths, userId)

        return ResponseEntity.ok(mapOf("message" to "Tokens revoked", "revokedCount" to deletedAuths.toString()))
    }
}
