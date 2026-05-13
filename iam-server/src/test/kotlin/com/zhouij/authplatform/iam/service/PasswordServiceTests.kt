package com.zhouij.authplatform.iam.service

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PasswordServiceTests {
    private val passwordService = PasswordService()

    @Test
    fun `seeded admin hash matches default admin password`() {
        val seededHash =
            "\$argon2id\$v=19\$m=131072,t=4,p=4\$GbjCGdzxxIZrt6YHc3CK3Q\$6fD7XeXKDpjLFz2EAbG2qAFYkGy4RMtfMRiMsU4HbMI"

        assertTrue(passwordService.matchesAdmin("admin123", seededHash))
    }
}
