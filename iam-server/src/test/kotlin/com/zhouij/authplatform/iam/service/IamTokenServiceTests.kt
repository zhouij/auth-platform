package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.config.IamSigningProperties
import com.zhouij.authplatform.iam.config.SigningKeyStore
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class IamTokenServiceTests {

    private fun keyStore(keyPath: String?, previousPaths: List<String>? = null): SigningKeyStore =
        SigningKeyStore(
            IamSigningProperties().apply {
                this.keyPath = keyPath
                this.previousKeyPaths = previousPaths
            }
        )

    @Test
    fun `token roundtrips through create and verify`(@TempDir tempDir: Path) {
        val service = IamTokenService(keyStore(tempDir.resolve("key.b64").toString()))

        val (token, claims) = service.createToken("user-1", "USER", "password-reset", 15)
        val verified = service.verifyToken(token, "password-reset")

        assertNotNull(verified)
        assertEquals(claims.sub, verified!!.sub)
        assertEquals(claims.jti, verified.jti)
        assertEquals("USER", verified.userType)
    }

    @Test
    fun `rejects a token with the wrong purpose`(@TempDir tempDir: Path) {
        val service = IamTokenService(keyStore(tempDir.resolve("key.b64").toString()))
        val (token, _) = service.createToken("user-1", "USER", "password-reset", 15)

        assertNull(service.verifyToken(token, "email-verification"))
    }

    @Test
    fun `rejects a tampered token`(@TempDir tempDir: Path) {
        val service = IamTokenService(keyStore(tempDir.resolve("key.b64").toString()))
        val (token, _) = service.createToken("user-1", "USER", "password-reset", 15)

        val tampered = token.dropLast(4) + "xxxx"
        assertNull(service.verifyToken(tampered, "password-reset"))
    }

    @Test
    fun `accepts tokens signed with a configured rotation key`(@TempDir tempDir: Path) {
        val oldKeyPath = tempDir.resolve("old.b64")
        val newKeyPath = tempDir.resolve("new.b64")

        // Sign a token with the "old" key store instance
        val oldService = IamTokenService(keyStore(oldKeyPath.toString()))
        val (token, _) = oldService.createToken("user-1", "USER", "password-reset", 15)

        // A fresh store with the old key as a rotation key must still verify it
        val rotatedService = IamTokenService(
            keyStore(newKeyPath.toString(), previousPaths = listOf(oldKeyPath.toString()))
        )
        val verified = rotatedService.verifyToken(token, "password-reset")
        assertNotNull(verified)
        assertEquals("user-1", verified!!.sub)
    }

    @Test
    fun `signing key file survives restart`(@TempDir tempDir: Path) {
        val keyPath = tempDir.resolve("key.b64").toString()
        val first = IamTokenService(keyStore(keyPath))
        val (token, _) = first.createToken("user-1", "USER", "password-reset", 15)

        // Simulate a restart: a brand-new store reading the same file
        val second = IamTokenService(keyStore(keyPath))
        assertNotNull(second.verifyToken(token, "password-reset"))
    }
}
