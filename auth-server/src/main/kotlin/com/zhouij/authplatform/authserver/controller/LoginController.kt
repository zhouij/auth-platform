package com.zhouij.authplatform.authserver.controller

import com.zhouij.authplatform.authserver.auth.IamClient
import com.zhouij.authplatform.authserver.auth.IamLoginAuthenticationToken
import com.zhouij.authplatform.authserver.auth.IamPrincipal
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import java.net.URI

@Controller
class LoginController(
    private val authenticationManager: AuthenticationManager,
    private val iamClient: IamClient,
    @param:Value("\${auth.login-success-url:/login/success}")
    private val defaultLoginSuccessUrl: String
) {
    private val logger = LoggerFactory.getLogger(LoginController::class.java)
    private val requestCache = HttpSessionRequestCache()

    @GetMapping("/login")
    fun loginPage(
        @RequestParam(required = false) error: String?,
        @RequestParam(required = false) logout: String?,
        model: Model
    ): String {
        if (error == null && logout == null && isAuthenticated(SecurityContextHolder.getContext().authentication)) {
            return "redirect:$defaultLoginSuccessUrl"
        }
        if (logout != null) model.addAttribute("logout", true)
        if (error != null) model.addAttribute("error", "Invalid email or password")
        if (iamClient.isCircuitOpen()) model.addAttribute("error", "Authentication temporarily unavailable")
        return "login"
    }

    @GetMapping("/login/success")
    fun loginSuccess(model: Model): String {
        val authentication = SecurityContextHolder.getContext().authentication
        if (!isAuthenticated(authentication)) return "redirect:/login"

        val principal = authentication?.principal as? IamPrincipal
        model.addAttribute("email", principal?.email ?: authentication?.name ?: "")
        model.addAttribute("username", principal?.username ?: "")
        model.addAttribute("userType", principal?.userType ?: "")
        model.addAttribute("authorities", authentication?.authorities?.map { it.authority } ?: emptyList<String>())
        return "login-success"
    }

    @PostMapping("/login")
    fun processLogin(
        @RequestParam email: String,
        @RequestParam password: String,
        @RequestParam("user_type") userType: String,
        request: HttpServletRequest,
        response: HttpServletResponse
    ): String {
        try {
            val authToken = IamLoginAuthenticationToken.unauthenticated(email, password, userType)
            val authenticated = authenticationManager.authenticate(authToken)
            SecurityContextHolder.getContext().authentication = authenticated
            request.session?.let { session ->
                // Persist the security context in the session for authorization code flow
                session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext())
            }
            val savedRequest = requestCache.getRequest(request, response)
            val redirectUrl = savedRequest
                ?.redirectUrl
                ?.takeUnless { isLoginUrl(it) }
                ?: defaultLoginSuccessUrl
            return "redirect:$redirectUrl"
        } catch (e: Exception) {
            logger.warn("Login failed: {}", e.message)
            return "redirect:/login?error"
        }
    }

    private fun isAuthenticated(authentication: Authentication?): Boolean {
        return authentication != null &&
            authentication.isAuthenticated &&
            authentication !is AnonymousAuthenticationToken
    }

    private fun isLoginUrl(url: String): Boolean {
        return runCatching { URI.create(url).path == "/login" }.getOrDefault(url == "/login")
    }
}
