package com.zhouij.authplatform.iam.service

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

    fun hashUser(password: String): String = userEncoder.encode(password)!!
    fun hashAdmin(password: String): String = adminEncoder.encode(password)!!

    fun matchesUser(rawPassword: String, encodedPassword: String): Boolean =
        userEncoder.matches(rawPassword, encodedPassword)

    fun matchesAdmin(rawPassword: String, encodedPassword: String): Boolean =
        adminEncoder.matches(rawPassword, encodedPassword)

    fun validatePasswordStrength(password: String): Boolean =
        password.length >= 8

    fun validateAdminPasswordStrength(password: String): Boolean =
        password.length >= 14
}
