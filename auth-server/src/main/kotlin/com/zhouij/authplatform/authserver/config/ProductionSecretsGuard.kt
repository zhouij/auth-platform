package com.zhouij.authplatform.authserver.config

import jakarta.annotation.PostConstruct
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component

/**
 * Fail-fast guard: in the `prod` profile, refuse to start when any of the
 * development default secrets is still in use.
 */
@Component
@Profile("prod")
class ProductionSecretsGuard(
    @Value("\${spring.datasource.password:}") private val dbPassword: String,
    @Value("\${iam.internal-token:}") private val internalToken: String,
    @Value("\${auth.signing.key-path:}") private val signingKeyPath: String
) {
    private val logger = LoggerFactory.getLogger(ProductionSecretsGuard::class.java)

    private val forbiddenSecrets = setOf(
        "auth_pass", "postgres_pass", "dev-internal-token", "secret", "password", ""
    )

    @PostConstruct
    fun failFastOnDefaultSecrets() {
        val problems = mutableListOf<String>()
        if (dbPassword in forbiddenSecrets) {
            problems += "spring.datasource.password is blank or a known dev default"
        }
        if (internalToken in forbiddenSecrets) {
            problems += "iam.internal-token is blank or a known dev default"
        }
        if (signingKeyPath.isBlank()) {
            problems += "auth.signing.key-path is not set (tokens would not survive restarts)"
        }
        if (problems.isNotEmpty()) {
            throw IllegalStateException(
                "Refusing to start in prod profile with production-unsafe secrets: ${problems.joinToString("; ")}"
            )
        }
        logger.info("Production secrets guard passed")
    }
}
