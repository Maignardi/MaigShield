package com.maigshield.sdk.internal

internal object NativeBridge {

    init {
        try {
            System.loadLibrary("maigshield")
        } catch (e: UnsatisfiedLinkError) {
            // Fatal load error: native core was tampered with or ABI unsupported
            throw SecurityException("MaigShield native security engine initialization failure", e)
        }
    }

    @JvmStatic
    external fun nativeInit(packageName: String?, initialCounter: Long): Boolean

    @JvmStatic
    external fun nativeScanIntegrity(): Long

    @JvmStatic
    external fun nativePackEnvelope(javaThreatFlags: Long, bindingHash: ByteArray?): ByteArray

    @JvmStatic
    external fun nativeOnTouchDown(
        x: Float,
        y: Float,
        pressure: Float,
        size: Float,
        touchMajor: Float,
        touchMinor: Float,
        deviceId: Int
    )

    @JvmStatic
    external fun nativeOnTouchMove(
        x: Float,
        y: Float,
        pressure: Float,
        size: Float,
        touchMajor: Float,
        touchMinor: Float
    )

    @JvmStatic
    external fun nativeOnTouchUp(x: Float, y: Float)

    @JvmStatic
    external fun nativeGetBotScore(): Int

    @JvmStatic
    external fun nativeGetDuressScore(): Int

    @JvmStatic
    external fun nativeTriggerHoneypot(honeypotId: Int)

    @JvmStatic
    external fun nativeUnscrambleFlags(
        scrambled: Long,
        salt: Long,
        timestampNs: Long,
        codeChecksum: Int
    ): Long

    @JvmStatic
    external fun nativeGetCodeChecksum(): Int
}
