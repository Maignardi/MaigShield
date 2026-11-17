package com.maigshield.sdk

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import com.maigshield.sdk.internal.NativeBridge
import com.maigshield.sdk.internal.crypto.DecryptedProofDiagnostic
import com.maigshield.sdk.internal.crypto.StrongBoxSigner
import com.maigshield.sdk.internal.screen.ScreenThreatMonitor
import java.security.MessageDigest
import java.security.PrivateKey
import java.util.concurrent.CopyOnWriteArrayList

class MaigShield private constructor(
    private val context: Context,
    val config: MaigShieldConfig
) {

    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val screenThreatMonitor = ScreenThreatMonitor(
        context = context,
        enableAccessibilityCheck = config.enableScreenThreatDetection,
        enableScreenMirrorCheck = config.enableScreenThreatDetection,
        enableTapjackingCheck = config.enableTapjackingProtection
    )

    private val strongBoxSigner = StrongBoxSigner(
        context = context,
        serverPublicKeyPem = config.serverPublicKeyPem,
        enableStrongBox = config.enableStrongBox,
        enforceAttestation = config.enforceHardwareAttestation
    )

    private val observers = CopyOnWriteArrayList<TelemetryObserver>()

    init {
        val lastCounter = prefs.getLong(KEY_MONOTONIC_COUNTER, 1L)
        NativeBridge.nativeInit(context.packageName, lastCounter)

        if (context is Application) {
            context.registerActivityLifecycleCallbacks(screenThreatMonitor)
        }
    }

    /**
     * Generates a zero-boolean cryptographic proof token (X-MaigShield-Proof)
     * bound to the HTTP method, endpoint, and payload.
     */
    fun mintProofToken(
        httpMethod: String? = null,
        urlPath: String? = null,
        requestBody: ByteArray? = null
    ): String {
        // Compute request binding hash: SHA-256(METHOD + PATH + SHA256(BODY))
        val bindingHash = if (httpMethod != null && urlPath != null) {
            val md = MessageDigest.getInstance("SHA-256")
            val bodyHash = md.digest(requestBody ?: ByteArray(0))

            md.reset()
            md.update(httpMethod.toByteArray(Charsets.UTF_8))
            md.update(urlPath.toByteArray(Charsets.UTF_8))
            md.digest(bodyHash)
        } else {
            ByteArray(32)
        }

        val javaFlags = screenThreatMonitor.getThreatFlags()
        val rawEnvelope = NativeBridge.nativePackEnvelope(javaFlags, bindingHash)

        // Increment persistent sequence counter safely
        val nextCounter = prefs.getLong(KEY_MONOTONIC_COUNTER, 1L) + 1L
        prefs.edit().putLong(KEY_MONOTONIC_COUNTER, nextCounter).apply()

        // Encrypt with Bank Public Key and sign via StrongBox / TEE
        val proofToken = strongBoxSigner.signAndEncryptEnvelope(rawEnvelope)

        observers.forEach { observer ->
            try {
                observer.onTokenMinted(proofToken)
            } catch (_: Throwable) {}
        }

        return proofToken
    }

    fun addTelemetryObserver(observer: TelemetryObserver) {
        observers.add(observer)
    }

    fun removeTelemetryObserver(observer: TelemetryObserver) {
        observers.remove(observer)
    }

    fun unscrambleDiagnosticFlags(scrambledFlags: Long, salt: Long, timestampNs: Long): Long {
        val codeChecksum = NativeBridge.nativeGetCodeChecksum()
        return NativeBridge.nativeUnscrambleFlags(scrambledFlags, salt, timestampNs, codeChecksum)
    }

    fun decryptDiagnosticProof(proofToken: String, testPrivateKey: PrivateKey): DecryptedProofDiagnostic {
        return StrongBoxSigner.decryptProofTokenForDiagnostics(proofToken, testPrivateKey)
    }

    fun getBotScore(): Int = NativeBridge.nativeGetBotScore()
    fun getDuressScore(): Int = NativeBridge.nativeGetDuressScore()

    interface TelemetryObserver {
        fun onTokenMinted(proofToken: String)
    }

    companion object {
        private const val PREFS_NAME = "com.maigshield.sdk.telemetry_store"
        private const val KEY_MONOTONIC_COUNTER = "key_monotonic_counter"

        @Volatile
        private var sInstance: MaigShield? = null

        @JvmStatic
        fun initialize(context: Context, config: MaigShieldConfig): MaigShield {
            return sInstance ?: synchronized(this) {
                sInstance ?: MaigShield(context.applicationContext, config).also {
                    sInstance = it
                }
            }
        }

        @JvmStatic
        fun getInstance(): MaigShield {
            return sInstance ?: throw IllegalStateException(
                "MaigShield must be initialized prior to usage. Call MaigShield.initialize(context, config)."
            )
        }
    }
}
