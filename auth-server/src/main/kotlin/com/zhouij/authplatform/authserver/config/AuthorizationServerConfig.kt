package com.zhouij.authplatform.authserver.config

import com.zhouij.authplatform.authserver.auth.IamPrincipal
import com.zhouij.authplatform.authserver.auth.ProfileEnrichingAuthorizationService
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import java.time.Duration
import java.util.UUID
import javax.sql.DataSource

@Configuration
class AuthorizationServerConfig {

    @Value("\${auth.issuer:http://localhost:9081}")
    private lateinit var issuer: String

    @Value("\${auth.token.audience:resource-server}")
    private lateinit var audience: String

    @Value("\${auth.token.access-ttl:15m}")
    private lateinit var accessTokenTtl: Duration

    @Value("\${auth.token.refresh-ttl:12h}")
    private lateinit var refreshTokenTtl: Duration

    @Bean
    fun registeredClientRepository(dataSource: DataSource): RegisteredClientRepository {
        // The decorator applies the operator-controlled token TTLs from
        // configuration on top of the DB-seeded clients, without mutating the
        // stored rows. Short access-token TTLs keep the revocation window
        // small (see /internal/auth/revoke-user/{id}).
        return TtlEnforcingRegisteredClientRepository(
            JdbcRegisteredClientRepository(JdbcTemplate(dataSource)),
            accessTokenTtl = accessTokenTtl,
            refreshTokenTtl = refreshTokenTtl
        )
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
            .issuer(issuer)
            .build()
    }

    @Bean
    fun tokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer { context ->
            val claimsBuilder = context.claims

            // Stable token id so access tokens can be denylisted on revocation
            // even when the authorization server itself doesn't add one.
            claimsBuilder.claims { claims ->
                if (!claims.containsKey("jti")) {
                    claims["jti"] = UUID.randomUUID().toString()
                }
            }

            claimsBuilder.claims { claims ->
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

                claimsBuilder.claims { claims ->
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

            claimsBuilder.claims { claims ->
                val aud = audience.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                claims["aud"] = aud
            }
        }
    }
}

/**
 * Applies operator-configured token TTLs to every registered client at read
 * time. The DB rows stay untouched, so this is safe to toggle without
 * migrations and applies uniformly to all clients.
 */
class TtlEnforcingRegisteredClientRepository(
    private val delegate: RegisteredClientRepository,
    private val accessTokenTtl: Duration,
    private val refreshTokenTtl: Duration
) : RegisteredClientRepository by delegate {

    private fun applyTokenSettings(client: RegisteredClient): RegisteredClient {
        val settings = TokenSettings.builder()
            .accessTokenTimeToLive(accessTokenTtl)
            .refreshTokenTimeToLive(refreshTokenTtl)
            .reuseRefreshTokens(false)
            .build()
        return RegisteredClient.from(client).tokenSettings(settings).build()
    }

    override fun findById(id: String): RegisteredClient? =
        delegate.findById(id)?.let(::applyTokenSettings)

    override fun findByClientId(clientId: String): RegisteredClient? =
        delegate.findByClientId(clientId)?.let(::applyTokenSettings)
}
