package com.zhouij.authplatform.gateway.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain

@Configuration
class SecurityConfig {

    @Value("\${gateway.public-paths}")
    private lateinit var publicPaths: List<String>

    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        http
            .csrf { it.disable() }
            .authorizeExchange { exchanges ->
                publicPaths.forEach { path ->
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
