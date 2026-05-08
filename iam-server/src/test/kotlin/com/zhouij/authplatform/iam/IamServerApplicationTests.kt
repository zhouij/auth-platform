package com.zhouij.authplatform.iam

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.postgresql.PostgreSQLContainer

@SpringBootTest
@Testcontainers
class IamServerApplicationTests {
    @Test
    fun contextLoads() {
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
