package com.zhouij.authplatform.webclient.controller

import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.reactive.function.client.WebClient

@Controller
class DashboardController(
    webClientBuilder: WebClient.Builder,
    @param:Value("\${gateway.base-url:http://localhost:9080}")
    private val gatewayBaseUrl: String
) {
    private val webClient = webClientBuilder.build()

    @GetMapping("/")
    fun dashboard(
        @AuthenticationPrincipal user: OidcUser,
        @RegisteredOAuth2AuthorizedClient("auth-platform") authorizedClient: OAuth2AuthorizedClient,
        model: Model
    ): String {
        val accessToken = authorizedClient.accessToken.tokenValue
        val iamStatus = getGatewayStatus("$gatewayBaseUrl/iam/v1/status", accessToken)
        val resourceStatus = getGatewayStatus("$gatewayBaseUrl/api/v1/status", accessToken)

        model.addAttribute("name", user.fullName ?: user.preferredUsername ?: user.email ?: user.subject)
        model.addAttribute("email", user.email ?: "")
        model.addAttribute("subject", user.subject)
        model.addAttribute("iamStatus", iamStatus)
        model.addAttribute("resourceStatus", resourceStatus)
        return "dashboard"
    }

    @GetMapping("/logged-out")
    fun loggedOut(): String = "logged-out"

    private fun getGatewayStatus(url: String, accessToken: String): Map<*, *> {
        return try {
            webClient.get()
                .uri(url)
                .headers { it.setBearerAuth(accessToken) }
                .retrieve()
                .bodyToMono(Map::class.java)
                .block() ?: mapOf("error" to "Empty response")
        } catch (e: Exception) {
            mapOf("error" to (e.message ?: "Request failed"))
        }
    }
}
