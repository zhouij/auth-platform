package com.zhouij.authplatform.authserver

import com.jayway.jsonpath.JsonPath
import com.sun.net.httpserver.HttpServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.MethodOrderer
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestMethodOrder
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.postgresql.PostgreSQLContainer
import java.net.CookieManager
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

/**
 * End-to-end OAuth2/OIDC flow tests against a real PostgreSQL and a stubbed
 * IAM (JDK HttpServer), driven over real HTTP so the full servlet/security
 * stack (sessions, CSRF, redirects, consent) is exercised exactly like a
 * browser: client_credentials, the authorization-code flow with PKCE + the
 * consent screen, consent reuse, and revocation denylisting.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(MethodOrderer.MethodName::class)
@ActiveProfiles("oauth-flow-test")
@Testcontainers
class OAuth2FlowIntegrationTests {

    @LocalServerPort
    var port: Int = 0

    private fun base(): String = "http://localhost:$port"

    private data class HttpResult(
        val status: Int,
        val headers: java.net.http.HttpHeaders,
        val body: String,
        val uri: URI
    ) {
        fun location(): String? = headers.firstValue("location").orElse(null)

        /** Resolve a possibly-relative Location header against the request URI. */
        fun redirectUrl(): String = location()?.let { uri.resolve(it).toString() } ?: ""
    }

    private fun clientWithCookies(): HttpClient = HttpClient.newBuilder()
        .cookieHandler(CookieManager())
        .followRedirects(HttpClient.Redirect.NEVER)
        .build()

    private fun get(client: HttpClient, url: String): HttpResult {
        val request = HttpRequest.newBuilder(URI.create(url)).GET().build()
        val response = sendWithRetry(client, request)
        return HttpResult(response.statusCode(), response.headers(), response.body(), URI.create(url))
    }

    /** Localhost connections occasionally refuse under test load — retry once. */
    private fun sendWithRetry(client: HttpClient, request: HttpRequest): HttpResponse<String> {
        try {
            return client.send(request, HttpResponse.BodyHandlers.ofString())
        } catch (e: java.net.ConnectException) {
            return client.send(request, HttpResponse.BodyHandlers.ofString())
        }
    }

    private fun postFormPairs(
        client: HttpClient,
        url: String,
        pairs: List<Pair<String, String>>
    ): HttpResult {
        val body = pairs.joinToString("&") { (k, v) ->
            "$k=${URLEncoder.encode(v, StandardCharsets.UTF_8)}"
        }
        val builder = HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
        val response = sendWithRetry(client, builder.build())
        return HttpResult(response.statusCode(), response.headers(), response.body(), URI.create(url))
    }

    private fun postForm(
        client: HttpClient,
        url: String,
        form: Map<String, String>,
        basicAuth: String? = null
    ): HttpResult {
        val body = form.entries.joinToString("&") { (k, v) ->
            "$k=${URLEncoder.encode(v, StandardCharsets.UTF_8)}"
        }
        val builder = HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
        if (basicAuth != null) {
            builder.header("Authorization", "Basic $basicAuth")
        }
        val response = sendWithRetry(client, builder.build())
        return HttpResult(response.statusCode(), response.headers(), response.body(), URI.create(url))
    }

    private fun basic(clientId: String, secret: String): String =
        Base64.getEncoder().encodeToString("$clientId:$secret".toByteArray())

    private fun loginAs(client: HttpClient, email: String, userType: String) {
        val loginPage = get(client, "${base()}/login")
        assertEquals(200, loginPage.status)
        val csrf = Regex("name=\"_csrf\" value=\"([^\"]+)\"").find(loginPage.body)!!.groupValues[1]
        val loginResult = postForm(
            client,
            "${base()}/login",
            mapOf("email" to email, "password" to "whatever", "user_type" to userType, "_csrf" to csrf)
        )
        assertEquals(302, loginResult.status, "login failed: ${loginResult.body}")
    }

    @Test
    fun `client credentials flow issues a JWT with the expected claims`() {
        val client = clientWithCookies()
        val response = postForm(
            client,
            "${base()}/oauth2/token",
            mapOf("grant_type" to "client_credentials", "scope" to "read"),
            basicAuth = basic("service-client", "service-secret")
        )
        assertEquals(200, response.status, "token endpoint failed: ${response.body}")
        val token = JsonPath.read<String>(response.body, "$.access_token")
        val claims = decodeJwt(token)

        assertEquals("http://localhost:9081", claims["iss"])
        assertEquals("service-client", claims["client_id"])
        assertEquals(listOf("read"), claims["scope"])
        assertNotNull(claims["jti"], "jti is required for denylist revocation")
        // SAS may render a single-element audience either as a string or array
        val aud = claims["aud"]
        assertTrue(
            aud == "resource-server" || aud == listOf("resource-server"),
            "unexpected aud: $aud"
        )

        val jwks = get(client, "${base()}/oauth2/jwks")
        assertEquals(200, jwks.status)
        val keyCount: Int = JsonPath.read(jwks.body, "$.keys.length()")
        assertTrue(keyCount >= 1)
    }

    @Test
    fun `authorization code flow with PKCE and consent issues tokens`() {
        val verifier = "pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
        val challenge = base64Url(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray()))
        val authorizeUri = authorizeUri(mapOf(
            "client_id" to "web-client",
            "response_type" to "code",
            "redirect_uri" to "http://localhost:9081/callback",
            "scope" to "openid profile read write",
            "state" to "flow-state",
            "code_challenge" to challenge,
            "code_challenge_method" to "S256"
        ))

        val client = clientWithCookies()

        // 1. Anonymous authorize -> login page
        val first = get(client, authorizeUri)
        assertEquals(302, first.status, "expected redirect to login, got ${first.status}: ${first.body}")
        assertTrue(first.redirectUrl().endsWith("/login"), "expected /login, got ${first.redirectUrl()}")

        // 2. Log in as the stubbed IAM user
        loginAs(client, "alice@example.com", "USER")

        // 3. Authorize again with the session -> consent page
        val consentPage = get(client, authorizeUri)
        assertEquals(302, consentPage.status, "expected consent redirect, got ${consentPage.status}: ${consentPage.body}")
        assertTrue(consentPage.redirectUrl().contains("/oauth2/consent"), "expected consent, got ${consentPage.redirectUrl()}")

        // 4. Load the consent page and scrape the session key from the state field
        val consentHtml = get(client, consentPage.redirectUrl())
        assertEquals(200, consentHtml.status)
        val consentState = Regex("name=\"state\" value=\"([^\"]+)\"").find(consentHtml.body)!!.groupValues[1]

        // 5. Approve the scopes (POST back to the authorize endpoint — SAS 7 flow)
        val callback = postFormPairs(
            client,
            "${base()}/oauth2/authorize",
            listOf(
                "client_id" to "web-client",
                "state" to consentState,
                "scope" to "openid",
                "scope" to "profile",
                "scope" to "read",
                "scope" to "write"
            )
        )
        assertEquals(302, callback.status, "consent POST failed: ${callback.status} ${callback.body}")
        assertTrue(
            callback.redirectUrl().startsWith("http://localhost:9081/callback?code="),
            "expected callback with code, got ${callback.redirectUrl()}"
        )
        val code = Regex("code=([^&]+)").find(callback.redirectUrl())!!.groupValues[1]
        assertTrue(callback.redirectUrl().contains("state=flow-state"))

        // 6. Exchange the code (PKCE)
        val tokenResponse = postForm(
            client,
            "${base()}/oauth2/token",
            mapOf(
                "grant_type" to "authorization_code",
                "code" to code,
                "redirect_uri" to "http://localhost:9081/callback",
                "code_verifier" to verifier
            ),
            basicAuth = basic("web-client", "secret")
        )
        assertEquals(200, tokenResponse.status, "token exchange failed: ${tokenResponse.body}")
        assertNotNull(JsonPath.read<String>(tokenResponse.body, "$.id_token"), "id_token expected for openid scope")
        assertNotNull(JsonPath.read<String>(tokenResponse.body, "$.refresh_token"))

        val claims = decodeJwt(JsonPath.read(tokenResponse.body, "$.access_token"))
        assertEquals(aliceId, claims["sub"])
        assertEquals("alice@example.com", claims["email"])
        assertEquals("alice", claims["preferred_username"])
        assertEquals("USER", claims["user_type"])
    }

    @Test
    fun `consent is remembered on a second authorize`() {
        // Runs after the authorization-code flow test, which approved the
        // consent for alice: a new authorize must skip the consent screen and
        // go straight to the callback with a fresh code.
        val verifier = "pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
        val challenge = base64Url(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray()))
        val authorizeUri = authorizeUri(mapOf(
            "client_id" to "web-client",
            "response_type" to "code",
            "redirect_uri" to "http://localhost:9081/callback",
            "scope" to "openid profile read write",
            "state" to "flow-state-2",
            "code_challenge" to challenge,
            "code_challenge_method" to "S256"
        ))

        val client = clientWithCookies()
        get(client, authorizeUri)
        loginAs(client, "alice@example.com", "USER")

        val second = get(client, authorizeUri)
        assertEquals(302, second.status, "authorize failed: ${second.body}")
        assertFalse(second.redirectUrl().contains("/oauth2/consent"), "consent should be remembered")
        assertTrue(
            second.redirectUrl().startsWith("http://localhost:9081/callback?code="),
            "expected direct code, got ${second.redirectUrl()}"
        )

        // The code must still be exchangeable (PKCE)
        val code = Regex("code=([^&]+)").find(second.redirectUrl())!!.groupValues[1]
        val tokenResponse = postForm(
            client,
            "${base()}/oauth2/token",
            mapOf(
                "grant_type" to "authorization_code",
                "code" to code,
                "redirect_uri" to "http://localhost:9081/callback",
                "code_verifier" to verifier
            ),
            basicAuth = basic("web-client", "secret")
        )
        assertEquals(200, tokenResponse.status, "token exchange failed: ${tokenResponse.body}")
        assertEquals(aliceId, decodeJwt(JsonPath.read(tokenResponse.body, "$.access_token"))["sub"])
    }

    @Test
    fun `revocation denylists the outstanding access token`() {
        val client = clientWithCookies()
        val response = postForm(
            client,
            "${base()}/oauth2/token",
            mapOf("grant_type" to "client_credentials", "scope" to "read"),
            basicAuth = basic("service-client", "service-secret")
        )
        val token = JsonPath.read<String>(response.body, "$.access_token")
        val jti = decodeJwt(token)["jti"] as String

        val revoke = HttpRequest.newBuilder(URI.create("${base()}/internal/auth/revoke-user/service-client"))
            .header("X-Internal-Token", internalToken)
            .POST(HttpRequest.BodyPublishers.noBody())
        val revokeResponse = client.send(revoke.build(), HttpResponse.BodyHandlers.ofString())
        assertEquals(200, revokeResponse.statusCode(), "revoke failed: ${revokeResponse.body()}")

        val check = HttpRequest.newBuilder(URI.create("${base()}/internal/tokens/revoked/$jti"))
            .header("X-Internal-Token", internalToken)
            .GET()
        val checkResponse = client.send(check.build(), HttpResponse.BodyHandlers.ofString())
        assertEquals(200, checkResponse.statusCode())
        assertEquals(true, JsonPath.read<Boolean>(checkResponse.body(), "$.revoked"))
    }

    private fun authorizeUri(params: Map<String, String>): String =
        "${base()}/oauth2/authorize?" + params.entries.joinToString("&") { (k, v) ->
            "$k=${URLEncoder.encode(v, StandardCharsets.UTF_8)}"
        }

    private fun decodeJwt(token: String): Map<String, Any> {
        val payload = token.split(".")[1]
        val json = String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8)
        @Suppress("UNCHECKED_CAST")
        return JsonPath.read(json, "$") as Map<String, Any>
    }

    private fun base64Url(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    companion object {
        val aliceId: String = UUID.randomUUID().toString()
        val internalToken: String = "test-internal-token"

        @Container
        @JvmStatic
        val postgres = PostgreSQLContainer("postgres:16-alpine")

        /** Stubbed IAM: answers credential validation for alice@example.com. */
        @JvmStatic
        val iamServer: HttpServer by lazy {
            HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
                createContext("/") { exchange ->
                    val response = """
                        {
                          "userId": "$aliceId",
                          "userType": "USER",
                          "email": "alice@example.com",
                          "username": "alice",
                          "firstName": "Alice",
                          "lastName": "Anderson",
                          "enabled": true,
                          "authorities": []
                        }
                    """.trimIndent().toByteArray(StandardCharsets.UTF_8)
                    exchange.responseHeaders.add("Content-Type", "application/json")
                    exchange.sendResponseHeaders(200, response.size.toLong())
                    exchange.responseBody.use { it.write(response) }
                }
                start()
                iamStarted = true
            }
        }

        @JvmStatic
        @Volatile
        var iamStarted: Boolean = false

        @JvmStatic
        val iamBaseUrl: String
            get() = "http://127.0.0.1:${iamServer.address.port}"

        @JvmStatic
        val signingKeyDir = Files.createTempDirectory("oauth-flow-jwk")

        @BeforeAll
        @JvmStatic
        fun touchIam() {
            // Force the stub to start before the context is created
            iamServer.address
        }

        @AfterAll
        @JvmStatic
        fun stopIam() {
            if (iamStarted) iamServer.stop(0)
        }

        @DynamicPropertySource
        @JvmStatic
        fun properties(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url", postgres::getJdbcUrl)
            registry.add("spring.datasource.username", postgres::getUsername)
            registry.add("spring.datasource.password", postgres::getPassword)
            registry.add("iam.base-url") { iamBaseUrl }
            registry.add("iam.internal-token") { internalToken }
            registry.add("auth.signing.key-path") { signingKeyDir.resolve("signing.jwk").toString() }
        }
    }
}
