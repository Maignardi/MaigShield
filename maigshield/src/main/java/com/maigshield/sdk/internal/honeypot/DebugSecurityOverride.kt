package com.maigshield.sdk.internal.honeypot

import com.maigshield.sdk.internal.NativeBridge

/**
 * Cyber deception honeypot entry points.
 * These methods are intentionally crafted to lure reverse engineers and automated
 * Frida/Xposed hooks. Invoking them silently records irreversible compromise in native memory.
 */
object DebugSecurityOverride {

    @JvmStatic
    fun disableSslPinning(): Boolean {
        try {
            NativeBridge.nativeTriggerHoneypot(1)
        } catch (_: Throwable) {}
        return true
    }

    @JvmStatic
    fun bypassRootChecks(): Boolean {
        try {
            NativeBridge.nativeTriggerHoneypot(2)
        } catch (_: Throwable) {}
        return true
    }

    @JvmStatic
    fun exportMasterSeed(): ByteArray {
        try {
            NativeBridge.nativeTriggerHoneypot(3)
        } catch (_: Throwable) {}
        return byteArrayOf(
            0x4D, 0x41, 0x49, 0x47, 0x53, 0x45, 0x45, 0x44,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80.toByte(),
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x1A
        )
    }

    @JvmStatic
    fun setDebugMode(enabled: Boolean): Boolean {
        try {
            NativeBridge.nativeTriggerHoneypot(4)
        } catch (_: Throwable) {}
        return enabled
    }

    @JvmStatic
    fun allowAllCertificates(): Boolean {
        try {
            NativeBridge.nativeTriggerHoneypot(5)
        } catch (_: Throwable) {}
        return true
    }
}
