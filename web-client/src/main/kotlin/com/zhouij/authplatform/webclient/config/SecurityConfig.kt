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
            .oauth2Login { }
            .logout { logout ->
                logout.logoutSuccessUrl("/logged-out")
            }

        return http.build()
    }
}
