package com.maigshield.sdk.internal.crypto

internal object SafeBase64 {
    fun encodeUrlSafe(bytes: ByteArray): String {
        return try {
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        } catch (_: Throwable) {
            android.util.Base64.encodeToString(
                bytes,
                android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING
            )
        }
    }

    fun decodeUrlSafe(str: String): ByteArray {
        return try {
            java.util.Base64.getUrlDecoder().decode(str.trim())
        } catch (_: Throwable) {
            android.util.Base64.decode(
                str.trim(),
                android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING
            )
        }
    }

    fun decodeStandard(str: String): ByteArray {
        val clean = str.replace("\\s".toRegex(), "")
        return try {
            java.util.Base64.getDecoder().decode(clean)
        } catch (_: Throwable) {
            android.util.Base64.decode(clean, android.util.Base64.DEFAULT)
        }
    }
}
