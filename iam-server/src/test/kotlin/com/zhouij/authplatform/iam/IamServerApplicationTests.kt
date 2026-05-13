package com.zhouij.authplatform.iam

import com.zhouij.authplatform.iam.service.AdminUserService
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.postgresql.PostgreSQLContainer

@SpringBootTest
@Testcontainers
class IamServerApplicationTests(
    @param:Autowired private val adminUserService: AdminUserService
) {
    @Test
    fun contextLoads() {
    }

    @Test
    fun `default admin can log in by email or username`() {
        assertNotNull(adminUserService.validateCredentials("admin@localhost", "admin123"))
        assertNotNull(adminUserService.validateCredentials("admin", "admin123"))
    }

    companion object {
        @Container
        @JvmStatic
        val postgres = PostgreSQLContainer("postgres:16-alpine")

        @DynamicPropertySource
        @JvmStatic
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url") { jdbcUrlWithCurrentSchema("iam") }
            registry.add("spring.datasource.username", postgres::getUsername)
            registry.add("spring.datasource.password", postgres::getPassword)
            registry.add("spring.jpa.properties.hibernate.default_schema") { "iam" }
        }

        private fun jdbcUrlWithCurrentSchema(schema: String): String {
            val separator = if (postgres.jdbcUrl.contains("?")) "&" else "?"
            return "${postgres.jdbcUrl}${separator}currentSchema=$schema"
        }
    }
}
