package com.maigshield.sdk

import com.maigshield.sdk.internal.crypto.SafeBase64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class SafeBase64Test {

    @Test
    fun test_url_safe_roundtrip_across_all_lengths() {
        val rng = SecureRandom()
        for (len in listOf(0, 1, 2, 3, 4, 15, 76, 255, 1024)) {
            val original = ByteArray(len).also { rng.nextBytes(it) }
            val encoded = SafeBase64.encodeUrlSafe(original)

            assertFalse("URL-safe output must not contain '+'", encoded.contains('+'))
            assertFalse("URL-safe output must not contain '/'", encoded.contains('/'))
            assertFalse("URL-safe output must not contain '=' padding", encoded.contains('='))
            assertFalse("URL-safe output must not contain newlines", encoded.contains('\n'))

            val decoded = SafeBase64.decodeUrlSafe(encoded)
            assertArrayEquals("Roundtrip failed for length $len", original, decoded)
        }
    }

    @Test
    fun test_standard_base64_decode_with_whitespace() {
        val original = "-----BEGIN PUBLIC KEY-----MaigShield-----END PUBLIC KEY-----".toByteArray()
        val encoded = java.util.Base64.getEncoder().encodeToString(original)
        val withNewlines = encoded.chunked(16).joinToString("\n")
        assertTrue(encoded.isNotEmpty())
        val decoded = SafeBase64.decodeStandard(withNewlines)
        assertArrayEquals(original, decoded)
    }
}
