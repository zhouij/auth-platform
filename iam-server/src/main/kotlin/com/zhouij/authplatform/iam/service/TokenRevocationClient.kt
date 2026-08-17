package com.zhouij.authplatform.iam.service

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient

/**
 * Best-effort client for the auth-server's internal revocation endpoint.
 * Used when an account is deleted (right to erasure): all outstanding
 * access/refresh tokens for the user are revoked so JWTs don't outlive the
 * account. Failures are logged, never propagated — account deletion proceeds
 * regardless, and short token TTLs bound the residual exposure.
 */
@Component
class TokenRevocationClient(
    @Value("\${iam.auth-server-base-url:http://localhost:9081}") private val authServerBaseUrl: String,
    @Value("\${iam.internal-token:dev-internal-token}") private val internalToken: String
) {
    private val logger = LoggerFactory.getLogger(TokenRevocationClient::class.java)

    private val restClient: RestClient = RestClient.create()

    fun revokeAllTokens(userId: String) {
        try {
            restClient.post()
                .uri("$authServerBaseUrl/internal/auth/revoke-user/{userId}", userId)
                .header("X-Internal-Token", internalToken)
                .retrieve()
                .toBodilessEntity()
            logger.info("Revoked all tokens for user {} via auth-server", userId)
        } catch (e: Exception) {
            logger.warn("Best-effort token revocation failed for user {}: {}", userId, e.message)
        }
    }
}
