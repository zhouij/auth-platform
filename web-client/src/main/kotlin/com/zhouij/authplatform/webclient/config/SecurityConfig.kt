package com.zhouij.authplatform.webclient.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class SecurityConfig {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorize ->
                authorize
                    .requestMatchers("/actuator/**", "/logged-out").permitAll()
                    .anyRequest().authenticated()
            }
            // No session-fixation protection: this BFF never authenticates
            // locally — the session only carries the pending OAuth2
            // authorization request, and changing the session id mid-flow
            // orphans that state (authorization_request_not_found).
            .sessionManagement { session ->
                session.sessionFixation { it.none() }
            }
            .oauth2Login { }
            .logout { logout ->
                logout.logoutSuccessUrl("/logged-out")
            }

        return http.build()
    }
}
