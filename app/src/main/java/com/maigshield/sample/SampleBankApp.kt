package com.maigshield.sample

import android.app.Application
import android.util.Base64
import com.maigshield.sdk.MaigShield
import com.maigshield.sdk.MaigShieldConfig
import com.maigshield.sdk.WarmUpMode
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey

class SampleBankApp : Application() {

    override fun onCreate() {
        super.onCreate()

        // Generate test RSA KeyPair for local demonstration and server simulation
        val testKeyPair = generateTestRsaKeyPair()
        sTestPrivateKey = testKeyPair.private
        val publicKeyPem = exportPublicKeyToPem(testKeyPair)
        sTestPublicKeyPem = publicKeyPem

        // Feature modules can register their own protected routes independently
        MaigShield.registerProtectedPaths("/api/v1/pix/transfer", "/api/v1/account")

        // Initialize MaigShield SDK with non-blocking background warm-up (zero TTFF/TTFI impact)
        val config = MaigShieldConfig.Builder()
            .setServerPublicKeyPem(publicKeyPem)
            .setWarmUpMode(WarmUpMode.BACKGROUND_ASYNC)
            .setEnableStrongBox(true)
            .setEnforceHardwareAttestation(true)
            .setEnableScreenThreatDetection(true)
            .setEnableTapjackingProtection(true)
            .setEnableBehavioralBiometrics(true)
            .setAllowDebuggable(true)
            .build()

        MaigShield.initialize(this, config)
    }

    private fun generateTestRsaKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        return kpg.generateKeyPair()
    }

    private fun exportPublicKeyToPem(keyPair: KeyPair): String {
        val base64Key = java.util.Base64.getEncoder().encodeToString(keyPair.public.encoded)
        return "-----BEGIN PUBLIC KEY-----\n$base64Key\n-----END PUBLIC KEY-----"
    }

    companion object {
        var sTestPrivateKey: PrivateKey? = null
            private set

        var sTestPublicKeyPem: String = ""
            private set
    }
}
