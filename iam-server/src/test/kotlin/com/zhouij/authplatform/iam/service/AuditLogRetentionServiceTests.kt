package com.zhouij.authplatform.iam.service

import com.zhouij.authplatform.iam.repository.AuditLogRepository
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.reset
import org.mockito.Mockito.verifyNoInteractions
import org.springframework.test.util.ReflectionTestUtils

class AuditLogRetentionServiceTests {

    private val repository = mock(AuditLogRepository::class.java)
    private val service = AuditLogRetentionService(repository)

    @BeforeEach
    fun setUp() {
        reset(repository)
        ReflectionTestUtils.setField(service, "retentionDays", 90)
    }

    @Test
    fun `skips pruning when retention is disabled`() {
        ReflectionTestUtils.setField(service, "retentionDays", 0)
        service.pruneExpiredEntries()
        verifyNoInteractions(repository)
    }

    @Test
    fun `treats negative retention as disabled`() {
        ReflectionTestUtils.setField(service, "retentionDays", -1)
        service.pruneExpiredEntries()
        verifyNoInteractions(repository)
    }
}
