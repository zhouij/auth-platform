package com.zhouij.authplatform.webclient

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest(
    properties = [
        "spring.security.oauth2.client.provider.auth-platform.authorization-uri=http://localhost:9081/oauth2/authorize",
        "spring.security.oauth2.client.provider.auth-platform.token-uri=http://localhost:9081/oauth2/token",
        "spring.security.oauth2.client.provider.auth-platform.jwk-set-uri=http://localhost:9081/oauth2/jwks",
        "spring.security.oauth2.client.provider.auth-platform.user-info-uri=http://localhost:9081/userinfo",
        "spring.security.oauth2.client.provider.auth-platform.user-name-attribute=sub"
    ]
)
class WebClientApplicationTests {
    @Test
    fun contextLoads() {
    }
}
