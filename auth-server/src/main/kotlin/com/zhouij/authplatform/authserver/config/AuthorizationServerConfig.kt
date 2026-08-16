package com.zhouij.authplatform.authserver.config

import com.zhouij.authplatform.authserver.auth.IamPrincipal
import com.zhouij.authplatform.authserver.auth.ProfileEnrichingAuthorizationService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
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
        val jdbcService = JdbcOAuth2AuthorizationService(JdbcTemplate(dataSource), registeredClientRepository)
        return ProfileEnrichingAuthorizationService(jdbcService)
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
                val iamPrincipal = when (principal) {
                    is IamPrincipal -> principal
                    is UsernamePasswordAuthenticationToken -> principal.principal as? IamPrincipal
                    else -> null
                }
                @Suppress("UNCHECKED_CAST")
                val profile: Map<String, Any> = if (iamPrincipal != null) {
                    mapOf(
                        "email" to iamPrincipal.email,
                        "preferred_username" to iamPrincipal.username,
                        "given_name" to iamPrincipal.firstName,
                        "family_name" to iamPrincipal.lastName,
                        "user_type" to iamPrincipal.userType,
                        "roles" to iamPrincipal.authorities
                            .mapNotNull { it.authority }
                            .filter { it.startsWith("ROLE_") }
                            .map { it.removePrefix("ROLE_") }
                    )
                } else {
                    // Persisted (refresh) form: profile stored as a plain map
                    (authorization.getAttribute<Map<String, Any>>(
                        ProfileEnrichingAuthorizationService.PROFILE_ATTRIBUTE
                    ) ?: emptyMap())
                }

                context.claims.claims { claims ->
                    claims["email"] = profile["email"]
                    claims["preferred_username"] = profile["preferred_username"]
                    claims["given_name"] = profile["given_name"]
                    claims["family_name"] = profile["family_name"]
                    claims["user_type"] = profile["user_type"]
                    @Suppress("UNCHECKED_CAST")
                    val roles = profile["roles"] as? List<String>
                    if (!roles.isNullOrEmpty()) {
                        claims["roles"] = roles
                    }
                }
            }

            context.claims.claims { claims ->
                claims["aud"] = listOf("resource-server")
            }
        }
    }
}
