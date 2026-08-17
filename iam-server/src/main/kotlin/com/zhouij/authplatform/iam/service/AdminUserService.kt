package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.domain.AdminUserEntity
import com.zhouij.authplatform.iam.repository.AdminGroupRepository
import com.zhouij.authplatform.iam.repository.AdminPasswordResetTokenRepository
import com.zhouij.authplatform.iam.repository.AdminUserRepository
import com.zhouij.authplatform.iam.repository.LoginAttemptRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.util.UUID

@Service
class AdminUserService(
    private val adminUserRepository: AdminUserRepository,
    private val adminGroupRepository: AdminGroupRepository,
    private val passwordService: PasswordService,
    private val adminPasswordResetTokenRepository: AdminPasswordResetTokenRepository,
    private val passwordHistoryService: PasswordHistoryService,
    private val loginAttemptRepository: LoginAttemptRepository
) {

    @Transactional
    fun createAdmin(
        email: String,
        password: String,
        firstName: String?,
        lastName: String?,
        groupNames: List<String>
    ): AdminUserEntity {
        require(!adminUserRepository.existsByEmailIgnoreCase(email)) { "Email already registered" }
        require(passwordService.validateAdminPasswordStrength(password)) { "Admin password must be at least 14 characters" }

        val groups = adminGroupRepository.findByNameIn(groupNames).toMutableSet()
        require(groups.isNotEmpty()) { "At least one valid group must be specified" }

        val admin = AdminUserEntity(
            email = email.lowercase(),
            username = email.substringBefore('@'),
            passwordHash = passwordService.hashAdmin(password),
            firstName = firstName,
            lastName = lastName,
            groups = groups
        )
        val saved = adminUserRepository.save(admin)
        passwordHistoryService.record(userId = null, adminUserId = saved.id, passwordHash = saved.passwordHash)
        return saved
    }

    fun validateCredentials(identifier: String, password: String): AdminUserEntity? {
        val admin = adminUserRepository.findByEmailIgnoreCase(identifier).orElse(null)
            ?: adminUserRepository.findByUsernameIgnoreCase(identifier).orElse(null)
            ?: return null
        if (!admin.enabled) return null
        if (!passwordService.matchesAdmin(password, admin.passwordHash)) return null
        return admin
    }

    fun findByEmail(email: String): AdminUserEntity? =
        adminUserRepository.findByEmailIgnoreCase(email).orElse(null)

    fun findById(id: UUID): AdminUserEntity? =
        adminUserRepository.findById(id).orElse(null)

    @Transactional
    fun recordLogin(admin: AdminUserEntity) {
        admin.lastLoginAt = Instant.now()
        admin.updatedAt = Instant.now()
        adminUserRepository.save(admin)
    }

    @Transactional
    fun changePassword(userId: UUID, currentPassword: String, newPassword: String): UserService.ChangePasswordResult {
        val admin = findById(userId) ?: return UserService.ChangePasswordResult.USER_NOT_FOUND
        if (!passwordService.matchesAdmin(currentPassword, admin.passwordHash))
            return UserService.ChangePasswordResult.WRONG_PASSWORD
        if (!passwordService.validateAdminPasswordStrength(newPassword))
            return UserService.ChangePasswordResult.WEAK_PASSWORD
        if (passwordHistoryService.wasUsedRecently(userId = null, adminUserId = userId, newPassword))
            return UserService.ChangePasswordResult.PASSWORD_REUSED

        admin.passwordHash = passwordService.hashAdmin(newPassword)
        admin.credentialsChangedAt = Instant.now()
        admin.updatedAt = Instant.now()
        adminUserRepository.save(admin)
        passwordHistoryService.record(userId = null, adminUserId = userId, passwordHash = admin.passwordHash)
        return UserService.ChangePasswordResult.SUCCESS
    }

    @Transactional
    fun updateProfile(userId: UUID, firstName: String?, lastName: String?, username: String?) {
        val admin = findById(userId) ?: throw NoSuchElementException("Admin not found")
        firstName?.let { admin.firstName = it }
        lastName?.let { admin.lastName = it }
        if (username != null && username != admin.username) {
            require(!adminUserRepository.existsByUsernameIgnoreCase(username)) { "Username already taken" }
            admin.username = username
        }
        admin.updatedAt = Instant.now()
        adminUserRepository.save(admin)
    }

    @Transactional(readOnly = true)
    fun listAll(): List<AdminUserEntity> = adminUserRepository.findAll()

    @Transactional
    fun disable(email: String): Boolean {
        val admin = findByEmail(email) ?: return false
        admin.enabled = false
        admin.credentialsChangedAt = Instant.now()
        admin.updatedAt = Instant.now()
        adminUserRepository.save(admin)
        return true
    }

    @Transactional
    fun enable(email: String): Boolean {
        val admin = findByEmail(email) ?: return false
        admin.enabled = true
        admin.updatedAt = Instant.now()
        adminUserRepository.save(admin)
        return true
    }

    @Transactional
    fun adminResetPassword(email: String, newPassword: String): Boolean {
        val admin = findByEmail(email) ?: return false
        require(passwordService.validateAdminPasswordStrength(newPassword)) { "Admin password must be at least 14 characters" }
        if (passwordHistoryService.wasUsedRecently(userId = null, adminUserId = admin.id, newPassword)) {
            throw IllegalArgumentException("Password was used recently")
        }
        admin.passwordHash = passwordService.hashAdmin(newPassword)
        admin.credentialsChangedAt = Instant.now()
        admin.updatedAt = Instant.now()
        adminUserRepository.save(admin)
        passwordHistoryService.record(userId = null, adminUserId = admin.id, passwordHash = admin.passwordHash)
        return true
    }

    @Transactional
    fun updateAdminDetails(
        email: String,
        firstName: String?,
        lastName: String?,
        username: String?,
        groupNames: List<String>?
    ) {
        val admin = findByEmail(email) ?: throw NoSuchElementException("Admin not found")
        firstName?.let { admin.firstName = it }
        lastName?.let { admin.lastName = it }
        if (username != null && username != admin.username) {
            require(!adminUserRepository.existsByUsernameIgnoreCase(username)) { "Username already taken" }
            admin.username = username
        }
        if (groupNames != null) {
            val groups = adminGroupRepository.findByNameIn(groupNames).toMutableSet()
            require(groups.isNotEmpty()) { "At least one valid group must be specified" }
            admin.groups = groups
        }
        admin.updatedAt = Instant.now()
        adminUserRepository.save(admin)
    }

    @Transactional(readOnly = true)
    fun listGroups() = adminGroupRepository.findAll()

    /**
     * Right to erasure for admin accounts: anonymizes, disables, detaches from
     * admin groups, and clears password history, reset tokens, and
     * login-attempt state. Outstanding JWTs are revoked via the auth-server.
     */
    @Transactional
    fun deleteAccount(userId: UUID) {
        val admin = findById(userId) ?: return
        val oldEmail = admin.email
        admin.email = "deleted-${admin.id}@anonymized.invalid"
        admin.username = null
        admin.firstName = null
        admin.lastName = null
        admin.enabled = false
        admin.groups = mutableSetOf()
        admin.credentialsChangedAt = Instant.now()
        admin.updatedAt = Instant.now()
        adminUserRepository.save(admin)

        adminPasswordResetTokenRepository.deleteByAdminUserId(userId)
        passwordHistoryService.deleteHistoryForAdmin(userId)
        loginAttemptRepository.deleteById(oldEmail.lowercase())
    }
}
