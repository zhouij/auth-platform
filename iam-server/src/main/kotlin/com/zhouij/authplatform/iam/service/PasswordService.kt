package com.zhouij.authplatform.iam.service

import org.springframework.beans.factory.annotation.Value
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class PasswordService {

    val userEncoder: PasswordEncoder = Argon2PasswordEncoder(
        16,     // salt length
        32,     // hash length
        4,      // parallelism
        65536,  // memory in KiB (64 MiB)
        3       // iterations
    )

    val adminEncoder: PasswordEncoder = Argon2PasswordEncoder(
        16,     // salt length
        32,     // hash length
        4,      // parallelism
        131072, // memory in KiB (128 MiB)
        4       // iterations
    )

    @Value("\${iam.password.common-check-enabled:true}")
    private var commonCheckEnabled: Boolean = true

    fun hashUser(password: String): String = userEncoder.encode(password)!!
    fun hashAdmin(password: String): String = adminEncoder.encode(password)!!

    fun matchesUser(rawPassword: String, encodedPassword: String): Boolean =
        userEncoder.matches(rawPassword, encodedPassword)

    fun matchesAdmin(rawPassword: String, encodedPassword: String): Boolean =
        adminEncoder.matches(rawPassword, encodedPassword)

    fun validatePasswordStrength(password: String): Boolean =
        password.length >= 8 && !isCommonPassword(password)

    fun validateAdminPasswordStrength(password: String): Boolean =
        password.length >= 14 && !isCommonPassword(password)

    /**
     * Lightweight breached/guessed-password gate: a curated blocklist of the
     * most common passwords (case-insensitive). Replace with a HIBP
     * k-anonymity lookup or zxcvbn scoring for stronger guarantees.
     */
    fun isCommonPassword(password: String): Boolean =
        commonCheckEnabled && password.lowercase() in COMMON_PASSWORDS

    companion object {
        private val COMMON_PASSWORDS: Set<String> = setOf(
            "password", "password1", "password12", "password123", "passw0rd", "p@ssw0rd",
            "123456", "1234567", "12345678", "123456789", "1234567890", "123123", "123321",
            "111111", "11111111", "121212", "000000", "555555", "654321", "666666",
            "696969", "888888", "112233", "qwerty", "qwerty123", "qwertyuiop", "1q2w3e4r",
            "1qaz2wsx", "qazwsx", "zaq12wsx", "asdfgh", "asdf123", "zxcvbn", "a1b2c3d4",
            "abc123", "abcd1234", "admin", "admin123", "administrator", "letmein", "welcome",
            "welcome1", "login", "master", "dragon", "monkey", "shadow", "superman",
            "batman", "trustno1", "sunshine", "iloveyou", "princess", "football", "baseball",
            "soccer", "hockey", "charlie", "mustang", "access", "hello", "freedom", "whatever",
            "secret", "changeme", "computer", "internet", "pokemon", "money", "peanut",
            "cheese", "hunter", "buster", "killer", "hottie", "flower", "ginger", "tigger",
            "thunder", "diamond", "starwars", "summer", "winter", "spring", "autumn",
            "cookie", "coffee", "banana", "orange", "purple", "silver", "golden"
        )
    }
}
