package com.zhouij.authplatform.iam.config

import com.zhouij.authplatform.iam.repository.AdminUserRepository
import com.zhouij.authplatform.iam.service.PasswordService
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import jakarta.annotation.PostConstruct

/**
 * Fail-fast guard: in the `prod` profile, refuse to start when any of the
 * development default secrets is still in use, so a misconfigured deployment
 * fails loudly at boot instead of silently running with known credentials.
 */
@Component
@Profile("prod")
class ProductionSecretsGuard(
    @Value("\${spring.datasource.password:}") private val dbPassword: String,
    @Value("\${iam.internal-token:}") private val internalToken: String,
    @Value("\${iam.signing.key-path:}") private val signingKeyPath: String
) {
    private val logger = LoggerFactory.getLogger(ProductionSecretsGuard::class.java)

    private val forbiddenSecrets = setOf(
        "iam_pass", "postgres_pass", "dev-internal-token", "secret", "password", "admin123", ""
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
            problems += "iam.signing.key-path is not set (tokens would not survive restarts)"
        }
        if (problems.isNotEmpty()) {
            throw IllegalStateException(
                "Refusing to start in prod profile with production-unsafe secrets: ${problems.joinToString("; ")}"
            )
        }
        logger.info("Production secrets guard passed")
    }
}

/**
 * Fail-fast guard for the seeded default admin account: in the `prod` profile,
 * refuse to start when any ENABLED admin account still verifies against a
 * well-known default password (admin123). Runs as an [ApplicationRunner] so
 * Flyway migrations have definitely completed before the check.
 */
@Component
@Profile("prod")
class SeededAdminPasswordGuard(
    private val adminUserRepository: AdminUserRepository,
    private val passwordService: PasswordService
) : ApplicationRunner {

    private val logger = LoggerFactory.getLogger(SeededAdminPasswordGuard::class.java)

    companion object {
        private val KNOWN_DEFAULT_PASSWORDS = listOf("admin123", "password", "password123", "changeme")
    }

    override fun run(args: ApplicationArguments) {
        val offenders = adminUserRepository.findAll()
            .filter { it.enabled }
            .filter { admin ->
                KNOWN_DEFAULT_PASSWORDS.any { default ->
                    passwordService.matchesAdmin(default, admin.passwordHash)
                }
            }
            .map { it.email }

        if (offenders.isNotEmpty()) {
            throw IllegalStateException(
                "Refusing to start in prod profile: enabled admin account(s) still use a known " +
                    "default password: ${offenders.joinToString(", ")}. Reset the password before deploying."
            )
        }
        logger.info("Seeded admin password guard passed")
    }
}
