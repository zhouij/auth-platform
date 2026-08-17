package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.domain.PasswordHistoryEntity
import com.zhouij.authplatform.iam.repository.PasswordHistoryRepository
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers
import org.mockito.Mockito.*
import org.springframework.data.domain.PageRequest
import org.springframework.test.util.ReflectionTestUtils
import java.util.UUID

class PasswordHistoryServiceTests {

    private val repository = mock(PasswordHistoryRepository::class.java)
    private val passwordService = PasswordService()
    private val service = PasswordHistoryService(repository, passwordService)

    private val userId = UUID.randomUUID()
    private val recentPage = PageRequest.of(0, 3)
    private val overflowPage = PageRequest.of(0, 103)

    @BeforeEach
    fun setUp() {
        reset(repository)
        ReflectionTestUtils.setField(service, "historySize", 3)
    }

    @Test
    fun `rejects a password matching a recent hash`() {
        val hash = passwordService.hashUser("OldPassword1")
        `when`(repository.findRecentForUser(userId, recentPage))
            .thenReturn(listOf(PasswordHistoryEntity(userId = userId, passwordHash = hash)))

        assertTrue(service.wasUsedRecently(userId, null, "OldPassword1"))
    }

    @Test
    fun `accepts a password that was never used`() {
        `when`(repository.findRecentForUser(userId, recentPage))
            .thenReturn(emptyList())

        assertFalse(service.wasUsedRecently(userId, null, "BrandNewPassword1"))
    }

    @Test
    fun `records a new entry and trims the overflow`() {
        val old = (1..5).map {
            PasswordHistoryEntity(
                id = it.toLong(),
                userId = userId,
                passwordHash = passwordService.hashUser("OldPassword$it")
            )
        }
        `when`(repository.findRecentForUser(userId, recentPage)).thenReturn(old.take(3))
        `when`(repository.findRecentForUser(userId, overflowPage)).thenReturn(old)
        `when`(repository.save(ArgumentMatchers.any(PasswordHistoryEntity::class.java)))
            .thenAnswer { inv -> inv.arguments[0] as PasswordHistoryEntity }

        service.record(userId, null, passwordService.hashUser("NewPassword1"))

        verify(repository).deleteAll(old.drop(3))
    }

    @Test
    fun `requires exactly one owner`() {
        assertThrows(IllegalArgumentException::class.java) {
            service.record(null, null, "hash")
        }
    }
}
