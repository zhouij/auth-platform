package com.zhouij.authplatform.gateway.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource

@Configuration
@EnableConfigurationProperties(GatewaySecurityProperties::class)
class SecurityConfig(
    private val properties: GatewaySecurityProperties
) {
    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        http
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .authorizeExchange { exchanges ->
                properties.publicPaths.forEach { path ->
                    exchanges.pathMatchers(path).permitAll()
                }
                exchanges.anyExchange().authenticated()
            }
            .oauth2ResourceServer { oauth2 ->
                oauth2.jwt { jwt ->
                    // JWKS URI configured via application.yml properties
                }
            }
            .headers { headers ->
                headers.contentTypeOptions { }
                headers.referrerPolicy { it.policy(org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN) }
                if (properties.hstsEnabled) {
                    headers.hsts { hsts ->
                        hsts.includeSubdomains(true).maxAge(java.time.Duration.ofDays(365))
                    }
                }
            }

        return http.build()
    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val source = UrlBasedCorsConfigurationSource()
        val allowedOrigins = properties.cors.allowedOrigins.filter { it.isNotBlank() }
        if (allowedOrigins.isNotEmpty()) {
            val config = CorsConfiguration().apply {
                setAllowedOrigins(allowedOrigins)
                setAllowedMethods(listOf("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"))
                setAllowedHeaders(listOf("*"))
                setExposedHeaders(listOf("Retry-After"))
                allowCredentials = true
                maxAge = 3600
            }
            source.registerCorsConfiguration("/**", config)
        }
        return source
    }
}

@ConfigurationProperties(prefix = "gateway")
class GatewaySecurityProperties {
    var publicPaths: List<String> = emptyList()

    /** Only meaningful behind TLS (set GATEWAY_HSTS_ENABLED=true in prod). */
    var hstsEnabled: Boolean = false

    var cors: CorsProperties = CorsProperties()
    var rateLimit: RateLimitProperties = RateLimitProperties()
    var revocationCheck: RevocationCheckProperties = RevocationCheckProperties()

    class CorsProperties {
        /** Comma-separated origins; empty = CORS disabled. */
        var allowedOrigins: List<String> = emptyList()
    }

    class RateLimitProperties {
        var enabled: Boolean = true
        var requestsPerMinute: Int = 30
        var paths: List<String> = listOf(
            "/iam/v1/auth/login",
            "/iam/v1/auth/register",
            "/iam/v1/auth/forgot-password"
        )
    }

    class RevocationCheckProperties {
        /** Denylist lookup against auth-server for presented JWTs (default off). */
        var enabled: Boolean = false
        var authServerBaseUrl: String = "http://localhost:9081"
        var internalToken: String = "dev-internal-token"
        var cacheSeconds: Long = 60
    }
}
