package com.maigshield.sdk

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.maigshield.sdk.internal.NativeBridge
import com.maigshield.sdk.internal.crypto.DecryptedProofDiagnostic
import com.maigshield.sdk.internal.crypto.StrongBoxSigner
import com.maigshield.sdk.internal.screen.ScreenThreatMonitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.Certificate
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class MaigShield private constructor(
    private val context: Context,
    val config: MaigShieldConfig
) {

    private val sdkScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val warmUpLock = Any()
    private val warmedUp = AtomicBoolean(false)

    private lateinit var prefs: SharedPreferences
    private val persistentCounter = AtomicLong(1L)

    private val screenThreatMonitor = ScreenThreatMonitor(
        context = context,
        enableAccessibilityCheck = config.enableScreenThreatDetection,
        enableScreenMirrorCheck = config.enableScreenThreatDetection,
        enableTapjackingCheck = config.enableTapjackingProtection,
        enableBehavioralBiometrics = config.enableBehavioralBiometrics
    )

    private val strongBoxSigner = StrongBoxSigner(
        context = context,
        serverPublicKeyPem = config.serverPublicKeyPem,
        enableStrongBox = config.enableStrongBox,
        enforceAttestation = config.enforceHardwareAttestation
    )

    private val observers = CopyOnWriteArrayList<TelemetryObserver>()
    private val manifestProtectedPaths = CopyOnWriteArraySet<String>()

    init {
        // Lightweight O(1) lifecycle registration on calling thread — zero impact on TTFF/TTFI
        if (context is Application) {
            context.registerActivityLifecycleCallbacks(screenThreatMonitor)
        }

        if (config.warmUpMode == WarmUpMode.BACKGROUND_ASYNC) {
            sdkScope.launch {
                ensureWarmedUp()
            }
        }
    }

    /**
     * Performs heavy initialization (SharedPreferences, Manifest metadata discovery,
     * native .so load + JNI_OnLoad, AndroidKeyStore/StrongBox key provisioning, and
     * initial Accessibility/Display scans). Safe to call multiple times or concurrently.
     */
    fun warmUp() {
        ensureWarmedUp()
    }

    private fun ensureWarmedUp() {
        if (warmedUp.get()) return
        synchronized(warmUpLock) {
            if (warmedUp.get()) return

            prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val lastCounter = prefs.getLong(KEY_MONOTONIC_COUNTER, 1L)
            persistentCounter.set(lastCounter)

            loadManifestProtectedPaths()
            NativeBridge.nativeInit(context.packageName, lastCounter)
            strongBoxSigner.warmUp()
            screenThreatMonitor.warmUp()

            warmedUp.set(true)
        }
    }

    private fun loadManifestProtectedPaths() {
        try {
            val appInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getApplicationInfo(
                    context.packageName,
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)
            }

            val metaData = appInfo.metaData ?: return

            // Support <meta-data android:name="com.maigshield.sdk.PROTECTED_PATHS" android:resource="@array/..." />
            val resId = metaData.getInt(META_PROTECTED_PATHS, 0)
            if (resId != 0) {
                context.resources.getStringArray(resId)
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                    .forEach { manifestProtectedPaths.add(it) }
                return
            }

            // Support <meta-data android:name="com.maigshield.sdk.PROTECTED_PATHS" android:value="/api/v1/pix,/api/v1/auth" />
            val rawString = metaData.getString(META_PROTECTED_PATHS)
            if (!rawString.isNullOrBlank()) {
                rawString.split(',')
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                    .forEach { manifestProtectedPaths.add(it) }
            }
        } catch (_: Throwable) {
            // Fail-safe: manifest metadata is optional
        }
    }

    /**
     * Returns the merged set of protected path prefixes from:
     * 1. AndroidManifest.xml `<meta-data android:name="com.maigshield.sdk.PROTECTED_PATHS" ... />`
     * 2. `MaigShieldConfig.protectedPaths`
     * 3. Feature modules via `MaigShield.registerProtectedPaths(...)`
     */
    fun getEffectiveProtectedPaths(): Set<String> {
        ensureWarmedUp()
        val combined = LinkedHashSet<String>(
            manifestProtectedPaths.size + config.protectedPaths.size + modularProtectedPaths.size
        )
        combined.addAll(manifestProtectedPaths)
        combined.addAll(config.protectedPaths)
        combined.addAll(modularProtectedPaths)
        return combined
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
        ensureWarmedUp()

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

        var javaFlags = screenThreatMonitor.getThreatFlags()
        if (!config.allowDebuggable &&
            (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        ) {
            javaFlags = javaFlags or FLAG_DEBUGGABLE_APP
        }

        val rawEnvelope = NativeBridge.nativePackEnvelope(javaFlags, bindingHash)

        // Increment persistent sequence counter atomically
        val nextCounter = persistentCounter.incrementAndGet()
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
        ensureWarmedUp()
        val codeChecksum = NativeBridge.nativeGetCodeChecksum()
        return NativeBridge.nativeUnscrambleFlags(scrambledFlags, salt, timestampNs, codeChecksum)
    }

    fun decryptDiagnosticProof(proofToken: String, testPrivateKey: PrivateKey): DecryptedProofDiagnostic {
        return StrongBoxSigner.decryptProofTokenForDiagnostics(proofToken, testPrivateKey)
    }

    fun getAttestationCertificateChain(): List<Certificate> {
        ensureWarmedUp()
        return strongBoxSigner.getAttestationCertificateChain()
    }

    /**
     * Returns the SHA-256 hex fingerprint of this installation's hardware-backed ECDSA public key.
     * Prefer binding server-side attestation records to this key ID + user/account ID rather than
     * ANDROID_ID/device_id, which resets on factory reset.
     */
    fun getAttestationKeyId(): String {
        ensureWarmedUp()
        return strongBoxSigner.getAttestationKeyId()
    }

    fun getBotScore(): Int {
        ensureWarmedUp()
        return NativeBridge.nativeGetBotScore()
    }

    fun getDuressScore(): Int {
        ensureWarmedUp()
        return NativeBridge.nativeGetDuressScore()
    }

    interface TelemetryObserver {
        fun onTokenMinted(proofToken: String)
    }

    companion object {
        private const val PREFS_NAME = "com.maigshield.sdk.telemetry_store"
        private const val KEY_MONOTONIC_COUNTER = "key_monotonic_counter"
        private const val META_PROTECTED_PATHS = "com.maigshield.sdk.PROTECTED_PATHS"
        private const val FLAG_DEBUGGABLE_APP = 1L shl 22

        private val modularProtectedPaths = CopyOnWriteArraySet<String>()

        @Volatile
        private var sInstance: MaigShield? = null

        /**
         * Allows feature modules (e.g. `:feature-pix`, `:feature-auth`) to register their own
         * protected endpoint prefixes independently, before or after `MaigShield.initialize()`.
         */
        @JvmStatic
        fun registerProtectedPaths(vararg paths: String) {
            paths.map { it.trim() }
                .filter { it.isNotEmpty() }
                .forEach { modularProtectedPaths.add(it) }
        }

        /**
         * Returns paths registered programmatically via `registerProtectedPaths(...)`.
         */
        @JvmStatic
        fun getRegisteredModularPaths(): Set<String> = modularProtectedPaths.toSet()

        @JvmStatic
        internal fun clearRegisteredModularPathsForTest() {
            modularProtectedPaths.clear()
        }

        @JvmStatic
        fun initialize(context: Context, config: MaigShieldConfig): MaigShield {
            return sInstance ?: synchronized(this) {
                val appContext = context.applicationContext ?: context
                sInstance ?: MaigShield(appContext, config).also {
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
