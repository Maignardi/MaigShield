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

    @Test
    fun warmUpMode_defaults_to_background_async_and_supports_lazy() {
        val defaultCfg = MaigShieldConfig.Builder()
            .setServerPublicKeyPem(sampleRsaPem)
            .build()
        assertEquals(WarmUpMode.BACKGROUND_ASYNC, defaultCfg.warmUpMode)

        val lazyCfg = MaigShieldConfig.Builder()
            .setServerPublicKeyPem(sampleRsaPem)
            .setWarmUpMode(WarmUpMode.LAZY_ON_DEMAND)
            .build()
        assertEquals(WarmUpMode.LAZY_ON_DEMAND, lazyCfg.warmUpMode)
    }

    @Test
    fun modular_protected_paths_register_and_deduplicate() {
        MaigShield.clearRegisteredModularPathsForTest()
        MaigShield.registerProtectedPaths(" /api/v1/pix ", "", "  ", "/api/v1/auth")
        MaigShield.registerProtectedPaths("/api/v1/pix", "/api/v1/cards")

        val registered = MaigShield.getRegisteredModularPaths()
        assertEquals(setOf("/api/v1/pix", "/api/v1/auth", "/api/v1/cards"), registered)
        MaigShield.clearRegisteredModularPathsForTest()
    }
}
