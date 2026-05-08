package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.domain.UserEntity
import com.zhouij.authplatform.iam.repository.UserPasswordResetTokenRepository
import com.zhouij.authplatform.iam.repository.UserRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.util.UUID

@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordService: PasswordService,
    private val userPasswordResetTokenRepository: UserPasswordResetTokenRepository
) {

    @Transactional
    fun register(email: String, password: String, firstName: String?, lastName: String?): UserEntity {
        require(!userRepository.existsByEmailIgnoreCase(email)) { "Email already registered" }
        require(passwordService.validatePasswordStrength(password)) { "Password must be at least 8 characters" }

        val user = UserEntity(
            email = email.lowercase(),
            username = firstName?.let { email.substringBefore('@') },
            passwordHash = passwordService.hashUser(password),
            firstName = firstName,
            lastName = lastName
        )
        return userRepository.save(user)
    }

    fun validateCredentials(email: String, password: String): UserEntity? {
        val user = userRepository.findByEmailIgnoreCase(email).orElse(null) ?: return null
        if (!user.enabled) return null
        if (!passwordService.matchesUser(password, user.passwordHash)) return null
        return user
    }

    fun findByEmail(email: String): UserEntity? =
        userRepository.findByEmailIgnoreCase(email).orElse(null)

    fun findById(id: UUID): UserEntity? =
        userRepository.findById(id).orElse(null)

    @Transactional
    fun recordLogin(user: UserEntity) {
        user.lastLoginAt = Instant.now()
        user.updatedAt = Instant.now()
        userRepository.save(user)
    }

    @Transactional
    fun changePassword(userId: UUID, currentPassword: String, newPassword: String): ChangePasswordResult {
        val user = findById(userId) ?: return ChangePasswordResult.USER_NOT_FOUND
        if (!passwordService.matchesUser(currentPassword, user.passwordHash))
            return ChangePasswordResult.WRONG_PASSWORD
        if (!passwordService.validatePasswordStrength(newPassword))
            return ChangePasswordResult.WEAK_PASSWORD

        user.passwordHash = passwordService.hashUser(newPassword)
        user.credentialsChangedAt = Instant.now()
        user.updatedAt = Instant.now()
        userRepository.save(user)
        return ChangePasswordResult.SUCCESS
    }

    @Transactional
    fun updateProfile(userId: UUID, firstName: String?, lastName: String?, username: String?) {
        val user = findById(userId) ?: throw NoSuchElementException("User not found")
        firstName?.let { user.firstName = it }
        lastName?.let { user.lastName = it }
        if (username != null && username != user.username) {
            require(!userRepository.existsByUsernameIgnoreCase(username)) { "Username already taken" }
            user.username = username
        }
        user.updatedAt = Instant.now()
        userRepository.save(user)
    }

    @Transactional(readOnly = true)
    fun listAll(): List<UserEntity> = userRepository.findAll()

    @Transactional
    fun disable(email: String): Boolean {
        val user = findByEmail(email) ?: return false
        user.enabled = false
        user.credentialsChangedAt = Instant.now()
        user.updatedAt = Instant.now()
        userRepository.save(user)
        return true
    }

    @Transactional
    fun enable(email: String): Boolean {
        val user = findByEmail(email) ?: return false
        user.enabled = true
        user.updatedAt = Instant.now()
        userRepository.save(user)
        return true
    }

    @Transactional
    fun adminResetPassword(email: String, newPassword: String): Boolean {
        val user = findByEmail(email) ?: return false
        require(passwordService.validatePasswordStrength(newPassword)) { "Password must be at least 8 characters" }
        user.passwordHash = passwordService.hashUser(newPassword)
        user.credentialsChangedAt = Instant.now()
        user.updatedAt = Instant.now()
        userRepository.save(user)
        return true
    }

    @Transactional
    fun adminUpdateProfile(email: String, firstName: String?, lastName: String?, username: String?) {
        val user = findByEmail(email) ?: throw NoSuchElementException("User not found")
        firstName?.let { user.firstName = it }
        lastName?.let { user.lastName = it }
        if (username != null && username != user.username) {
            require(!userRepository.existsByUsernameIgnoreCase(username)) { "Username already taken" }
            user.username = username
        }
        user.updatedAt = Instant.now()
        userRepository.save(user)
    }

    enum class ChangePasswordResult {
        SUCCESS, USER_NOT_FOUND, WRONG_PASSWORD, WEAK_PASSWORD
    }
}
