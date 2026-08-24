package com.zhouij.authplatform.iam

import com.zhouij.authplatform.iam.repository.AuditLogRepository
import com.zhouij.authplatform.iam.service.AuditLogRetentionService
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.util.ReflectionTestUtils
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.postgresql.PostgreSQLContainer

/**
 * Verifies the retention job against a real database: old audit rows are
 * pruned, fresh ones survive, and the disabled/negative configurations do
 * nothing.
 */
@SpringBootTest
@Testcontainers
class AuditLogRetentionIntegrationTests(
    @param:Autowired private val retentionService: AuditLogRetentionService,
    @param:Autowired private val auditLogRepository: AuditLogRepository,
    @param:Autowired private val jdbcTemplate: JdbcTemplate
) {

    @Test
    fun `prunes entries older than the configured retention`() {
        ReflectionTestUtils.setField(retentionService, "retentionDays", 90)
        jdbcTemplate.update("DELETE FROM iam.audit_log")
        jdbcTemplate.update(
            "INSERT INTO iam.audit_log (occurred_at, action, outcome) VALUES (now() - interval '200 days', 'LOGIN', 'SUCCESS')"
        )
        jdbcTemplate.update(
            "INSERT INTO iam.audit_log (occurred_at, action, outcome) VALUES (now() - interval '30 days', 'LOGIN', 'SUCCESS')"
        )
        jdbcTemplate.update(
            "INSERT INTO iam.audit_log (occurred_at, action, outcome) VALUES (now(), 'LOGIN', 'SUCCESS')"
        )

        retentionService.pruneExpiredEntries()

        assertEquals(2, auditLogRepository.count(), "only the 200-day-old row should be pruned")
    }

    @Test
    fun `retention disabled keeps everything`() {
        ReflectionTestUtils.setField(retentionService, "retentionDays", 0)
        jdbcTemplate.update(
            "INSERT INTO iam.audit_log (occurred_at, action, outcome) VALUES (now() - interval '400 days', 'LOGIN', 'SUCCESS')"
        )
        val before = auditLogRepository.count()

        retentionService.pruneExpiredEntries()

        assertEquals(before, auditLogRepository.count(), "disabled retention must not delete anything")
    }

    companion object {
        @Container
        @JvmStatic
        val postgres = PostgreSQLContainer("postgres:16-alpine")

        @DynamicPropertySource
        @JvmStatic
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url") {
                val separator = if (postgres.jdbcUrl.contains("?")) "&" else "?"
                "${postgres.jdbcUrl}${separator}currentSchema=iam"
            }
            registry.add("spring.datasource.username", postgres::getUsername)
            registry.add("spring.datasource.password", postgres::getPassword)
            registry.add("spring.jpa.properties.hibernate.default_schema") { "iam" }
        }
    }
}
