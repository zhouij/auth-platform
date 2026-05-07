package com.zhouij.authplatform.authserver.config

import com.zhouij.authplatform.authserver.auth.IamPrincipal
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.web.SecurityFilterChain
import javax.sql.DataSource

@Configuration
class AuthorizationServerConfig {

    @Bean
    @Order(1)
    fun authorizationServerSecurityFilterChain(
        http: HttpSecurity,
        context: ConfigurableApplicationContext
    ): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
            .oidc { oidc -> oidc }
        return http.build()
    }

    @Bean
    fun registeredClientRepository(dataSource: DataSource): RegisteredClientRepository {
        return JdbcRegisteredClientRepository(JdbcTemplate(dataSource))
    }

    @Bean
    fun authorizationService(
        dataSource: DataSource,
        registeredClientRepository: RegisteredClientRepository
    ): OAuth2AuthorizationService {
        return JdbcOAuth2AuthorizationService(
            JdbcTemplate(dataSource),
            registeredClientRepository
        )
    }

    @Bean
    fun authorizationConsentService(
        dataSource: DataSource,
        registeredClientRepository: RegisteredClientRepository
    ): OAuth2AuthorizationConsentService {
        return JdbcOAuth2AuthorizationConsentService(
            JdbcTemplate(dataSource),
            registeredClientRepository
        )
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

            // Add user-specific claims for authorization code flows
            val authorization = context.getAuthorization()
            if (authorization != null) {
                val principalName = authorization.principalName
                val attributes = authorization.getAttributes()

                @Suppress("UNCHECKED_CAST")
                val principal = attributes.getOrDefault(
                    "java.security.Principal", null
                )

                if (principal is IamPrincipal) {
                    context.claims.claims { claims ->
                        claims["email"] = principal.email
                        claims["preferred_username"] = principal.username
                        claims["given_name"] = principal.firstName
                        claims["family_name"] = principal.lastName
                        claims["user_type"] = principal.userType
                        if (principal.userType == "ADMIN") {
                            claims["roles"] = principal.authorities
                                .map { it.authority }
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
