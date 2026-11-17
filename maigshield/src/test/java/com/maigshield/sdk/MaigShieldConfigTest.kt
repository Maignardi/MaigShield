package com.maigshield.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MaigShieldConfigTest {

    private val sampleRsaPem = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy0t...
        -----END PUBLIC KEY-----
    """.trimIndent()

    @Test
    fun builder_creates_valid_immutable_config() {
        val config = MaigShieldConfig.Builder()
            .setServerPublicKeyPem(sampleRsaPem)
            .setProtectedPaths(listOf("/api/v1/pix", "/api/v1/login"))
            .setEnableStrongBox(true)
            .setEnforceHardwareAttestation(true)
            .setEnableScreenThreatDetection(true)
            .setEnableTapjackingProtection(true)
            .setEnableBehavioralBiometrics(true)
            .setAllowDebuggable(false)
            .build()

        assertEquals(sampleRsaPem, config.serverPublicKeyPem)
        assertEquals(listOf("/api/v1/pix", "/api/v1/login"), config.protectedPaths)
        assertTrue(config.enableStrongBox)
        assertTrue(config.enforceHardwareAttestation)
        assertTrue(config.enableScreenThreatDetection)
        assertTrue(config.enableTapjackingProtection)
        assertTrue(config.enableBehavioralBiometrics)
        assertFalse(config.allowDebuggable)
    }

    @Test(expected = IllegalArgumentException::class)
    fun builder_throws_on_empty_public_key() {
        MaigShieldConfig.Builder()
            .setServerPublicKeyPem("   ")
            .build()
    }
}
