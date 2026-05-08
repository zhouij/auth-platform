package com.zhouij.authplatform.resourceserver

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.postgresql.PostgreSQLContainer

@SpringBootTest
@Testcontainers
class ResourceServerApplicationTests {
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
            registry.add("spring.datasource.url") { jdbcUrlWithCurrentSchema("resource_app") }
            registry.add("spring.datasource.username", postgres::getUsername)
            registry.add("spring.datasource.password", postgres::getPassword)
            registry.add("spring.jpa.properties.hibernate.default_schema") { "resource_app" }
        }

        private fun jdbcUrlWithCurrentSchema(schema: String): String {
            val separator = if (postgres.jdbcUrl.contains("?")) "&" else "?"
            return "${postgres.jdbcUrl}${separator}currentSchema=$schema"
        }
    }
}
