package com.zhouij.authplatform.authserver.config

import com.zhouij.authplatform.authserver.auth.IamPrincipal
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import javax.sql.DataSource

@Configuration
class AuthorizationServerConfig {

    @Bean
    fun registeredClientRepository(dataSource: DataSource): RegisteredClientRepository {
        return JdbcRegisteredClientRepository(JdbcTemplate(dataSource))
    }

    @Bean
    fun authorizationService(
        dataSource: DataSource,
        registeredClientRepository: RegisteredClientRepository
    ): OAuth2AuthorizationService {
        return JdbcOAuth2AuthorizationService(JdbcTemplate(dataSource), registeredClientRepository)
    }

    @Bean
    fun authorizationConsentService(
        dataSource: DataSource,
        registeredClientRepository: RegisteredClientRepository
    ): OAuth2AuthorizationConsentService {
        return JdbcOAuth2AuthorizationConsentService(JdbcTemplate(dataSource), registeredClientRepository)
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder()
            .issuer("http://localhost:9081")
            .build()
    }

    @Bean
    fun tokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer { context ->
            context.claims.claims { claims ->
                claims["client_id"] = context.registeredClient.clientId
            }

            val authorization = context.getAuthorization()
            if (authorization != null) {
                val principal = authorization.getAttribute<Any>("java.security.Principal")
                if (principal is IamPrincipal) {
                    context.claims.claims { claims ->
                        claims["email"] = principal.email
                        claims["preferred_username"] = principal.username
                        claims["given_name"] = principal.firstName
                        claims["family_name"] = principal.lastName
                        claims["user_type"] = principal.userType
                        if (principal.userType == "ADMIN") {
                            claims["roles"] = principal.authorities
                                .mapNotNull { it.authority }
                                .filter { it.startsWith("ROLE_") }
                                .map { it.removePrefix("ROLE_") }
                        }
                    }
                }
            }

            context.claims.claims { claims ->
                claims["aud"] = listOf("resource-server")
            }
        }
    }
}
