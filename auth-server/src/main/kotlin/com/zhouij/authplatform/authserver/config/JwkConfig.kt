package com.zhouij.authplatform.authserver.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.slf4j.LoggerFactory
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.jwt.JwtDecoder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64

/**
 * JWK source backed by a persisted key file.
 *
 * - If [AuthSigningProperties.keyPath] points at an existing JWKSet JSON file,
 *   the key set is loaded from disk. The FIRST key in the set is used for
 *   signing; any additional keys stay in the set so the JWKS/JWT decoder keeps
 *   accepting tokens signed before a rotation.
 * - If the file does not exist, an RSA-2048 key pair is generated, persisted to
 *   that path (owner-only permissions) with a deterministic `kid` derived from
 *   the public key material, and used as the single key.
 * - If no path is configured (local development), an ephemeral in-memory key
 *   is generated with a warning — every restart invalidates outstanding tokens.
 *
 * Rotation procedure: generate a new key, write it as the FIRST key of the JWK
 * set file (keep the old keys after it), and restart. New tokens use the new
 * `kid`; old tokens keep validating until every service's JWKS cache has
 * refreshed and the old tokens have expired.
 */
@Configuration
@EnableConfigurationProperties(AuthSigningProperties::class)
class JwkConfig(
    private val properties: AuthSigningProperties
) {
    private val logger = LoggerFactory.getLogger(JwkConfig::class.java)

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keySet = loadOrCreateKeySet()
        val activeKey = keySet.keys.first() as? RSAKey
            ?: throw IllegalStateException("Signing key set must contain an RSA key")
        logger.info(
            "JWK source initialized: active kid={}, {} key(s) total, source={}",
            activeKey.keyID,
            keySet.keys.size,
            if (properties.keyPath.isNullOrBlank()) "ephemeral" else properties.keyPath
        )
        return ImmutableJWKSet(keySet)
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

    private fun loadOrCreateKeySet(): JWKSet {
        val path = properties.keyPath?.trim()?.takeIf { it.isNotEmpty() }
            ?: return ephemeralKeySet()

        val keyFile = Paths.get(path)
        return if (Files.exists(keyFile)) {
            loadKeySet(keyFile)
        } else {
            createAndPersistKeySet(keyFile)
        }
    }

    private fun loadKeySet(keyFile: Path): JWKSet {
        return try {
            val json = Files.readString(keyFile, StandardCharsets.UTF_8)
            val keySet = JWKSet.parse(json)
            if (keySet.keys.none { it is RSAKey && it.isPrivate }) {
                throw IllegalStateException("Signing key file ${keyFile.toAbsolutePath()} contains no private RSA key")
            }
            keySet
        } catch (e: Exception) {
            throw IllegalStateException("Failed to load signing keys from ${keyFile.toAbsolutePath()}: ${e.message}", e)
        }
    }

    private fun createAndPersistKeySet(keyFile: Path): JWKSet {
        val keyPair = generateKeyPair()
        val rsaKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyID(stableKeyId(keyPair.public as RSAPublicKey))
            .build()

        val json = JWKSet(rsaKey).toString(false) // include private key material
        try {
            Files.createDirectories(keyFile.toAbsolutePath().parent)
            Files.writeString(keyFile, json, StandardCharsets.UTF_8)
            try {
                Files.setPosixFilePermissions(
                    keyFile,
                    PosixFilePermissions.fromString("rw-------")
                )
            } catch (e: UnsupportedOperationException) {
                // Non-POSIX filesystem (e.g. Windows dev box) — best effort only
            }
            logger.info("Generated and persisted new signing key with kid={} at {}", rsaKey.keyID, keyFile.toAbsolutePath())
        } catch (e: Exception) {
            throw IllegalStateException("Failed to persist signing key to ${keyFile.toAbsolutePath()}: ${e.message}", e)
        }
        return JWKSet(rsaKey)
    }

    private fun ephemeralKeySet(): JWKSet {
        logger.warn(
            "auth.signing.key-path is not set — using an EPHEMERAL signing key. " +
                "All issued tokens will fail validation after a restart. " +
                "Set AUTH_SIGNING_KEY_PATH in production."
        )
        val keyPair = generateKeyPair()
        return JWKSet(
            RSAKey.Builder(keyPair.public as RSAPublicKey)
                .privateKey(keyPair.private as RSAPrivateKey)
                .keyID(stableKeyId(keyPair.public as RSAPublicKey))
                .build()
        )
    }

    private fun generateKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        return generator.generateKeyPair()
    }

    /**
     * Deterministic key id: base64url(SHA-256(public key DER)) truncated to 16
     * chars. Stable across restarts for the same key material.
     */
    private fun stableKeyId(publicKey: RSAPublicKey): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKey.encoded)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest).take(16)
    }
}

@ConfigurationProperties(prefix = "auth.signing")
class AuthSigningProperties {
    /** Path to a JWKSet JSON file holding the signing keys (first key = active). */
    var keyPath: String? = null
}
