package com.zhouij.authplatform.authserver.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class JwkConfigTests {

    private fun persistedKeys(keyPath: Path): JWKSet = JWKSet.parse(Files.readString(keyPath))

    @Test
    fun `generates and persists a signing key when the file is missing`(@TempDir tempDir: Path) {
        val keyPath = tempDir.resolve("signing.jwk")
        JwkConfig(AuthSigningProperties().apply { this.keyPath = keyPath.toString() }).jwkSource()

        assertTrue(Files.exists(keyPath), "Key file must be persisted")
        val key = persistedKeys(keyPath).keys.first() as RSAKey
        assertTrue(key.isPrivate, "Persisted key must include private material for signing")
        assertNotNull(key.keyID)
        assertEquals(2048, key.toRSAPublicKey().modulus.bitLength())
    }

    @Test
    fun `reloads the same kid and key from the persisted file`(@TempDir tempDir: Path) {
        val keyPath = tempDir.resolve("signing.jwk")
        val properties = AuthSigningProperties().apply { this.keyPath = keyPath.toString() }

        JwkConfig(properties).jwkSource()
        val first = persistedKeys(keyPath).keys.first() as RSAKey

        // "Restart": a fresh instance must reuse the file, not rewrite it
        val contentBeforeReload = Files.readString(keyPath)
        JwkConfig(properties).jwkSource()
        val second = persistedKeys(keyPath).keys.first() as RSAKey

        assertEquals(contentBeforeReload, Files.readString(keyPath), "reload must not rewrite the key file")
        assertEquals(first.keyID, second.keyID, "kid must be stable across restarts")
        assertEquals(
            first.toRSAPublicKey().encoded.toList(),
            second.toRSAPublicKey().encoded.toList(),
            "public key must be identical across restarts"
        )
    }

    @Test
    fun `fails fast when the persisted file contains no private key`(@TempDir tempDir: Path) {
        val keyPath = tempDir.resolve("signing.jwk")
        val properties = AuthSigningProperties().apply { this.keyPath = keyPath.toString() }

        JwkConfig(properties).jwkSource()
        val publicOnly = persistedKeys(keyPath).keys.first() as RSAKey
        Files.writeString(keyPath, JWKSet(publicOnly.toPublicJWK()).toString())

        assertThrows(IllegalStateException::class.java) {
            JwkConfig(properties).jwkSource()
        }
    }

    @Test
    fun `falls back to an ephemeral key without a configured path`() {
        val source = JwkConfig(AuthSigningProperties()).jwkSource()
        assertNotNull(source, "ephemeral mode must still provide a JWK source")
    }
}
