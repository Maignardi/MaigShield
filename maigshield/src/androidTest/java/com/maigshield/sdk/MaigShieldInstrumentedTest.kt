package com.maigshield.sdk

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maigshield.sdk.internal.honeypot.DebugSecurityOverride
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.ServerSocket
import java.security.KeyPairGenerator
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class MaigShieldInstrumentedTest {

    @Test
    fun test_real_android_end_to_end_native_and_frida_artifacts() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext

        val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val serverKeyPair = kpg.generateKeyPair()
        val pubPem = "-----BEGIN PUBLIC KEY-----\n" +
            Base64.getEncoder().encodeToString(serverKeyPair.public.encoded) +
            "\n-----END PUBLIC KEY-----"

        val config = MaigShieldConfig.Builder()
            .setServerPublicKeyPem(pubPem)
            .setWarmUpMode(WarmUpMode.LAZY_ON_DEMAND)
            .setEnableStrongBox(true)
            .setEnforceHardwareAttestation(true)
            .setAllowDebuggable(true)
            .build()

        val shield = MaigShield.initialize(context, config)
        shield.warmUp()

        // 1. Clean baseline across multiple consecutive calls (verifies PTRACE_TRACEME call_once fix)
        val body1 = """{"amount":100}""".toByteArray()
        val token1 = shield.mintProofToken("POST", "/api/v1/pix/transfer", body1)
        val token2 = shield.mintProofToken("POST", "/api/v1/pix/transfer", body1)

        val diag1 = shield.decryptDiagnosticProof(token1, serverKeyPair.private)
        val diag2 = shield.decryptDiagnosticProof(token2, serverKeyPair.private)
        assertEquals(0x4D414947, diag1.magic)
        assertTrue("Monotonic counter must advance", diag2.counter > diag1.counter)

        val cleanFlags1 = shield.unscrambleDiagnosticFlags(diag1.scrambledFlags, diag1.salt, diag1.timestampNs)
        val cleanFlags2 = shield.unscrambleDiagnosticFlags(diag2.scrambledFlags, diag2.salt, diag2.timestampNs)

        val flagTracerPid = 1L shl 0
        val flagFridaAgent = 1L shl 1
        val flagHoneypot = 1L shl 7
        val flagFridaPort = 1L shl 13
        val flagFridaThread = 1L shl 14

        assertEquals("Clean device must not false-positive TracerPid on 1st call", 0L, cleanFlags1 and flagTracerPid)
        assertEquals("Clean device must not false-positive TracerPid on 2nd call", 0L, cleanFlags2 and flagTracerPid)
        assertEquals(0L, cleanFlags2 and flagFridaAgent)
        assertEquals(0L, cleanFlags2 and flagHoneypot)

        // Verify hardware attestation key ID is non-empty 64-char SHA-256 hex
        val keyId = shield.getAttestationKeyId()
        assertEquals(64, keyId.length)

        // 2. Simulate Frida internal thread ("gum-js-loop") + Frida default TCP port (27042) + Honeypot
        val threadStarted = CountDownLatch(1)
        val stopThread = CountDownLatch(1)
        val fridaThread = Thread({
            threadStarted.countDown()
            stopThread.await(5, TimeUnit.SECONDS)
        }, "gum-js-loop")
        fridaThread.start()
        threadStarted.await(2, TimeUnit.SECONDS)

        var mockFridaSocket: ServerSocket? = null
        try {
            mockFridaSocket = ServerSocket(27042, 1, InetAddress.getByName("127.0.0.1"))
        } catch (_: Throwable) {
            // Port may already be bound on host/emulator
        }

        // Trigger cyber-deception honeypot
        val decoyResult = DebugSecurityOverride.disableSslPinning()
        assertTrue(decoyResult)

        val tokenAttacked = shield.mintProofToken("POST", "/api/v1/pix/transfer", body1)
        val diagAttacked = shield.decryptDiagnosticProof(tokenAttacked, serverKeyPair.private)
        val attackedFlags = shield.unscrambleDiagnosticFlags(
            diagAttacked.scrambledFlags,
            diagAttacked.salt,
            diagAttacked.timestampNs
        )

        stopThread.countDown()
        fridaThread.join(2000)
        mockFridaSocket?.close()

        assertNotEquals("Honeypot flag must be set", 0L, attackedFlags and flagHoneypot)
        assertNotEquals("Frida gum-js-loop thread must be detected via sys_getdents64", 0L, attackedFlags and flagFridaThread)
        if (mockFridaSocket != null) {
            assertNotEquals("Frida port 27042 (:69A2) must be detected in /proc/net/tcp", 0L, attackedFlags and flagFridaPort)
        }
    }
}
