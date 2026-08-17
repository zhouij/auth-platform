package com.zhouij.authplatform.iam.config

import io.jsonwebtoken.security.Keys
import org.slf4j.LoggerFactory
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.util.Base64
import jakarta.annotation.PostConstruct
import javax.crypto.SecretKey

/**
 * Provides the symmetric signing key used for IAM-issued self-contained tokens
 * (password reset, email verification).
 *
 * - If [IamSigningProperties.keyPath] points at an existing file, its base64
 *   content is loaded as the HMAC key.
 * - If the file does not exist, a fresh 256-bit key is generated and persisted
 *   (owner-only permissions) so tokens survive restarts.
 * - Additional rotation keys can be listed in [IamSigningProperties.previousKeyPaths];
 *   verification accepts any of them while new tokens are always signed with
 *   the current key.
 * - No path configured = ephemeral dev key (warning logged).
 */
@Configuration
@EnableConfigurationProperties(IamSigningProperties::class)
class SigningKeyStore(
    private val properties: IamSigningProperties
) {
    private val logger = LoggerFactory.getLogger(SigningKeyStore::class.java)

    private val currentKey: SecretKey by lazy { loadCurrentKey() }
    private val previousKeys: List<SecretKey> by lazy { loadPreviousKeys() }

    /** All keys, current first — used for verification. */
    val verificationKeys: List<SecretKey>
        get() = listOf(currentKey) + previousKeys

    fun signingKey(): SecretKey = currentKey

    private fun loadCurrentKey(): SecretKey {
        val path = properties.keyPath?.trim()?.takeIf { it.isNotEmpty() }
            ?: run {
                logger.warn(
                    "iam.signing-key-path is not set — using an EPHEMERAL signing key. " +
                        "Password-reset and verification links will be invalid after a restart. " +
                        "Set IAM_SIGNING_KEY_PATH in production."
                )
                return generateKey()
            }

        val keyFile = Paths.get(path)
        return if (Files.exists(keyFile)) {
            try {
                val encoded = Files.readString(keyFile, StandardCharsets.UTF_8).trim()
                Keys.hmacShaKeyFor(Base64.getDecoder().decode(encoded))
            } catch (e: Exception) {
                throw IllegalStateException("Failed to load signing key from ${keyFile.toAbsolutePath()}: ${e.message}", e)
            }
        } else {
            val key = generateKey()
            try {
                Files.createDirectories(keyFile.toAbsolutePath().parent)
                Files.writeString(
                    keyFile,
                    Base64.getEncoder().encodeToString(key.encoded),
                    StandardCharsets.UTF_8
                )
                try {
                    Files.setPosixFilePermissions(keyFile, PosixFilePermissions.fromString("rw-------"))
                } catch (e: UnsupportedOperationException) {
                    // Non-POSIX filesystem — best effort only
                }
                logger.info("Generated and persisted new IAM signing key at {}", keyFile.toAbsolutePath())
            } catch (e: Exception) {
                throw IllegalStateException("Failed to persist signing key to ${keyFile.toAbsolutePath()}: ${e.message}", e)
            }
            key
        }
    }

    private fun loadPreviousKeys(): List<SecretKey> {
        val paths = properties.previousKeyPaths ?: emptyList()
        return paths.mapNotNull { rawPath ->
            val path = rawPath.trim().takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            try {
                val encoded = Files.readString(Path.of(path), StandardCharsets.UTF_8).trim()
                Keys.hmacShaKeyFor(Base64.getDecoder().decode(encoded))
            } catch (e: Exception) {
                logger.warn("Skipping unreadable previous signing key at {}: {}", path, e.message)
                null
            }
        }
    }

    private fun generateKey(): SecretKey {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Keys.hmacShaKeyFor(bytes)
    }

    @PostConstruct
    fun logStatus() {
        // Force eager initialization so a broken key file fails startup loudly.
        val key = signingKey()
        val source = if (properties.keyPath.isNullOrBlank()) "ephemeral" else properties.keyPath
        logger.info("IAM token signing key ready: source={}, algorithm={}, rotationKeys={}", source, key.algorithm, previousKeys.size)
    }
}

@ConfigurationProperties(prefix = "iam.signing")
class IamSigningProperties {
    /** Path to a file containing a base64-encoded 32-byte HMAC key. */
    var keyPath: String? = null

    /** Optional paths to retired keys still accepted for verification. */
    var previousKeyPaths: List<String>? = null
}
