package com.maigshield.sdk

import com.maigshield.sdk.internal.honeypot.DebugSecurityOverride
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HoneypotSecurityTest {

    @Test
    fun honeypot_methods_execute_convincingly_without_exceptions() {
        val sslResult = DebugSecurityOverride.disableSslPinning()
        assertTrue("Honeypot must convincingly return true to fool hookers", sslResult)

        val rootResult = DebugSecurityOverride.bypassRootChecks()
        assertTrue("Honeypot must convincingly return true to fool hookers", rootResult)

        val seed = DebugSecurityOverride.exportMasterSeed()
        assertEquals(32, seed.size)

        val debugResult = DebugSecurityOverride.setDebugMode(true)
        assertTrue(debugResult)

        val certResult = DebugSecurityOverride.allowAllCertificates()
        assertTrue(certResult)
    }
}
