package com.zhouij.authplatform.authserver.config

import com.zhouij.authplatform.authserver.auth.IamAuthenticationProvider
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Value("\${auth.security.hsts-enabled:false}")
    private var hstsEnabled: Boolean = false

    @Bean
    fun authenticationManager(iamAuthenticationProvider: IamAuthenticationProvider): AuthenticationManager =
        ProviderManager(iamAuthenticationProvider)

    @Bean
    @Order(1)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .securityMatcher("/oauth2/**", "/.well-known/**", "/connect/**", "/userinfo")
            .oauth2AuthorizationServer { authorizationServer ->
                authorizationServer.oidc(Customizer.withDefaults())
                authorizationServer.authorizationEndpoint { endpoint ->
                    // Send unauthenticated browser requests to the login page
                    // (preserving the authorize request), instead of failing the
                    // OAuth flow with an "invalid_request" error redirect.
                    endpoint.errorResponseHandler { request, response, exception ->
                        val codeRequest =
                            (exception as? OAuth2AuthorizationCodeRequestAuthenticationException)
                                ?.authorizationCodeRequestAuthentication
                        if (codeRequest != null && !codeRequest.isAuthenticated) {
                            HttpSessionRequestCache().saveRequest(request, response)
                            response.sendRedirect("/login")
                        } else {
                            response.sendError(HttpServletResponse.SC_BAD_REQUEST)
                        }
                    }
                }
            }
            .exceptionHandling { exceptions ->
                // Send browser requests to the login page when the resource
                // owner is not authenticated (e.g. /oauth2/authorize).
                exceptions.defaultAuthenticationEntryPointFor(
                    LoginUrlAuthenticationEntryPoint("/login"),
                    MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            }
        return http.build()
    }

    @Bean
    @Order(2)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorize ->
                authorize
                    .requestMatchers("/actuator/**").permitAll()
                    .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
                    .requestMatchers(HttpMethod.GET, "/login").permitAll()
                    .requestMatchers(HttpMethod.POST, "/login").permitAll()
                    // Protected by X-Internal-Token header check in the controller
                    .requestMatchers("/internal/**").permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin { form ->
                form
                    .loginPage("/login")
                    .loginProcessingUrl("/spring-security-login")
                    .permitAll()
            }
            .csrf { csrf ->
                csrf.ignoringRequestMatchers("/actuator/**", "/internal/**")
            }
            .headers { headers ->
                headers.frameOptions { it.disable() }
                headers.contentTypeOptions { }
                headers.referrerPolicy { it.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN) }
                if (hstsEnabled) {
                    // Behind TLS only — enabled via AUTH_HSTS_ENABLED in prod.
                    headers.httpStrictTransportSecurity { hsts ->
                        hsts.includeSubDomains(true).maxAgeInSeconds(31536000)
                    }
                }
            }

        return http.build()
    }
}
