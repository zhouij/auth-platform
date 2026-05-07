package com.zhouij.authplatform.authserver.config

import com.zhouij.authplatform.authserver.auth.IamLoginAuthenticationToken
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    @Order(2)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorize ->
                authorize
                    .requestMatchers("/actuator/**").permitAll()
                    .requestMatchers("/.well-known/**").permitAll()
                    .requestMatchers("/oauth2/jwks").permitAll()
                    .requestMatchers("/login").permitAll()
                    .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin { form ->
                form
                    .loginPage("/login")
                    .loginProcessingUrl("/login")
                    .permitAll()
            }
            .csrf { csrf ->
                csrf.ignoringRequestMatchers("/actuator/**")
            }
            .sessionManagement { session ->
                session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            }
            .headers { headers ->
                headers.frameOptions { it.disable() }
            }

        return http.build()
    }
}
