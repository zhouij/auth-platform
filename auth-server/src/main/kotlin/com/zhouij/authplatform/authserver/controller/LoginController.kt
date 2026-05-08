package com.zhouij.authplatform.authserver.controller

import com.zhouij.authplatform.authserver.auth.IamClient
import com.zhouij.authplatform.authserver.auth.IamLoginAuthenticationToken
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam

@Controller
class LoginController(
    private val authenticationManager: AuthenticationManager,
    private val iamClient: IamClient
) {
    private val logger = LoggerFactory.getLogger(LoginController::class.java)

    @GetMapping("/login")
    fun loginPage(
        @RequestParam(required = false) error: String?,
        @RequestParam(required = false) logout: String?,
        model: Model
    ): String {
        if (logout != null) model.addAttribute("logout", true)
        if (error != null) model.addAttribute("error", "Invalid email or password")
        if (iamClient.isCircuitOpen()) model.addAttribute("error", "Authentication temporarily unavailable")
        return "login"
    }

    @PostMapping("/login")
    fun processLogin(
        @RequestParam email: String,
        @RequestParam password: String,
        @RequestParam("user_type") userType: String,
        request: HttpServletRequest
    ): String {
        try {
            val authToken = IamLoginAuthenticationToken.unauthenticated(email, password, userType)
            val authenticated = authenticationManager.authenticate(authToken)
            SecurityContextHolder.getContext().authentication = authenticated
            request.session?.let { session ->
                // Persist the security context in the session for authorization code flow
                session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext())
            }
            return "redirect:/oauth2/authorize"
        } catch (e: Exception) {
            logger.warn("Login failed: {}", e.message)
            return "redirect:/login?error"
        }
    }
}
