package com.zhouij.authplatform.resourceserver.config

import jakarta.annotation.PostConstruct
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component

/**
 * Fail-fast guard: in the `prod` profile, refuse to start when the dev default
 * database password is still in use.
 */
@Component
@Profile("prod")
class ProductionSecretsGuard(
    @Value("\${spring.datasource.password:}") private val dbPassword: String
) {
    private val logger = LoggerFactory.getLogger(ProductionSecretsGuard::class.java)

    private val forbiddenSecrets = setOf(
        "resource_pass", "postgres_pass", "secret", "password", ""
    )

    @PostConstruct
    fun failFastOnDefaultSecrets() {
        if (dbPassword in forbiddenSecrets) {
            throw IllegalStateException(
                "Refusing to start in prod profile with a production-unsafe spring.datasource.password"
            )
        }
        logger.info("Production secrets guard passed")
    }
}
