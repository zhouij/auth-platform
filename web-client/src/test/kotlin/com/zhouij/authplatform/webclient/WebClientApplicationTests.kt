package com.zhouij.authplatform.webclient

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.postgresql.PostgreSQLContainer

@SpringBootTest(
    properties = [
        "spring.security.oauth2.client.provider.auth-platform.authorization-uri=http://localhost:9081/oauth2/authorize",
        "spring.security.oauth2.client.provider.auth-platform.token-uri=http://localhost:9081/oauth2/token",
        "spring.security.oauth2.client.provider.auth-platform.jwk-set-uri=http://localhost:9081/oauth2/jwks",
        "spring.security.oauth2.client.provider.auth-platform.user-info-uri=http://localhost:9081/userinfo",
        "spring.security.oauth2.client.provider.auth-platform.user-name-attribute=sub"
    ]
)
@Testcontainers
class WebClientApplicationTests {
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
            registry.add("spring.datasource.url", postgres::getJdbcUrl)
            registry.add("spring.datasource.username", postgres::getUsername)
            registry.add("spring.datasource.password", postgres::getPassword)
        }
    }
}
