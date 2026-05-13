package com.zhouij.authplatform.authserver.controller

import com.zhouij.authplatform.authserver.auth.IamClient
import com.zhouij.authplatform.authserver.auth.IamLoginAuthenticationToken
import com.zhouij.authplatform.authserver.auth.IamPrincipal
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.authority.SimpleGrantedAuthority

class LoginControllerTests {
    private val controller = LoginController(
        authenticationManager = AuthenticationManager {
            IamLoginAuthenticationToken.authenticated(
                principal = IamPrincipal(
                    userId = "admin-id",
                    email = "admin@localhost",
                    username = "admin",
                    firstName = "System",
                    lastName = "Administrator",
                    userType = "ADMIN",
                    enabled = true,
                    authorities = listOf(SimpleGrantedAuthority("ROLE_ADMIN"))
                ),
                credentials = "admin123",
                authorities = listOf(SimpleGrantedAuthority("ROLE_ADMIN"))
            )
        },
        iamClient = IamClient("http://localhost:9083", "dev-internal-token"),
        defaultLoginSuccessUrl = "/login/success"
    )

    @Test
    fun `successful direct login redirects to login success page`() {
        val result = controller.processLogin(
            email = "admin",
            password = "admin123",
            userType = "ADMIN",
            request = MockHttpServletRequest(),
            response = MockHttpServletResponse()
        )

        assertEquals("redirect:/login/success", result)
    }
}
