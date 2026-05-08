package com.zhouij.authplatform.gateway.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain

@Configuration
@EnableConfigurationProperties(GatewaySecurityProperties::class)
class SecurityConfig(
    private val properties: GatewaySecurityProperties
) {
    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        http
            .csrf { it.disable() }
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

        return http.build()
    }
}

@ConfigurationProperties(prefix = "gateway")
class GatewaySecurityProperties {
    var publicPaths: List<String> = emptyList()
}
