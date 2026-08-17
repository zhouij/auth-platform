package com.zhouij.authplatform.authserver.controller

import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import java.security.Principal

/**
 * Custom consent PAGE for the authorization code flow. When a client has
 * `require_authorization_consent` enabled, the authorization server redirects
 * here before issuing a code; the user reviews and approves (or denies) the
 * requested scopes.
 *
 * Only the GET page is custom: the POST back to /oauth2/consent is handled by
 * the authorization server itself (it resumes the saved authorize request and
 * redirects to the client), so the form must post `client_id`, `scope` (one
 * entry per approved scope) and `state` — no custom submit controller needed.
 */
@Controller
class ConsentController(
    private val registeredClientRepository: RegisteredClientRepository,
    private val authorizationConsentService: OAuth2AuthorizationConsentService
) {

    @GetMapping("/oauth2/consent")
    fun consent(
        principal: Principal,
        model: Model,
        @RequestParam("client_id") clientId: String,
        @RequestParam("scope") scope: String,
        @RequestParam("state") state: String,
        @RequestParam(name = "user_code", required = false) userCode: String?
    ): String {
        val client = registeredClientRepository.findByClientId(clientId)
            ?: throw IllegalArgumentException("Unknown client: $clientId")
        val scopesToApprove = scope.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()

        // NOTE: consent rows are keyed by the RegisteredClient's internal id
        // (UUID), not the client_id string.
        val previousConsent = authorizationConsentService.findById(client.id, principal.name)
        val scopesWithApproval = client.scopes.associateWith { clientScope ->
            clientScope in scopesToApprove && (previousConsent == null || clientScope !in previousConsent.scopes)
        }

        model.addAttribute("clientId", client.clientId)
        model.addAttribute("clientName", client.clientName)
        model.addAttribute("state", state)
        model.addAttribute("principalName", principal.name)
        model.addAttribute("scopes", scopesWithApproval)
        model.addAttribute("redirectUri", client.redirectUris.firstOrNull() ?: "")
        model.addAttribute("userCode", userCode)
        return "consent"
    }
}
