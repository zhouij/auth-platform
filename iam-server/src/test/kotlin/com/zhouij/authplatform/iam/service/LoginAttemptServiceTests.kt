package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.domain.LoginAttemptEntity
import com.zhouij.authplatform.iam.repository.LoginAttemptRepository
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.*
import org.springframework.test.util.ReflectionTestUtils
import java.time.Instant
import java.util.Optional

class LoginAttemptServiceTests {

    private val repository = mock(LoginAttemptRepository::class.java)
    private val service = LoginAttemptService(repository)

    // Simple in-memory stand-in for the JPA repository
    private val store = mutableMapOf<String, LoginAttemptEntity>()

    @BeforeEach
    fun setUp() {
        reset(repository)
        store.clear()
        ReflectionTestUtils.setField(service, "maxAttempts", 3)
        ReflectionTestUtils.setField(service, "lockoutMinutes", 15L)
        ReflectionTestUtils.setField(service, "windowMinutes", 15L)

        `when`(repository.findById(anyString())).thenAnswer { inv ->
            Optional.ofNullable(store[inv.arguments[0] as String])
        }
        `when`(repository.save(any(LoginAttemptEntity::class.java))).thenAnswer { inv ->
            val entity = inv.arguments[0] as LoginAttemptEntity
            store[entity.email] = entity
            entity
        }
        doAnswer { inv -> store.remove(inv.arguments[0] as String) }
            .`when`(repository).deleteById(anyString())
        doAnswer { inv -> store.remove((inv.arguments[0] as LoginAttemptEntity).email) }
            .`when`(repository).delete(any(LoginAttemptEntity::class.java))
    }

    @Test
    fun `locks the account after the configured number of failures`() {
        service.recordFailure("a@b.c")
        service.recordFailure("A@B.C")
        service.recordFailure("a@b.c")

        assertNotNull(service.lockoutRemaining("a@b.c"), "account must be locked after 3 failures")
    }

    @Test
    fun `success clears the failure state`() {
        service.recordFailure("a@b.c")
        service.recordFailure("a@b.c")
        service.recordSuccess("a@b.c")

        assertNull(service.lockoutRemaining("a@b.c"))
        assertFalse(store.containsKey("a@b.c"))
    }

    @Test
    fun `expired lockout is lazily cleared`() {
        val past = Instant.now().minusSeconds(60)
        store["a@b.c"] = LoginAttemptEntity(email = "a@b.c", failedCount = 5, lockedUntil = past)

        assertNull(service.lockoutRemaining("a@b.c"))
        assertFalse(store.containsKey("a@b.c"), "stale lockout row must be removed")
    }

    @Test
    fun `failure count resets when the window has passed`() {
        val old = Instant.now().minusSeconds(30 * 60)
        store["a@b.c"] = LoginAttemptEntity(email = "a@b.c", failedCount = 2, firstFailedAt = old, lastFailedAt = old)

        service.recordFailure("a@b.c")
        assertNull(service.lockoutRemaining("a@b.c"), "old failures must not accumulate toward lockout")
        assertEquals(1, store["a@b.c"]!!.failedCount, "count must restart from 1 after the window")
    }
}
