package com.maigshield.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import java.security.MessageDigest

class RequestBindingHashTest {

    private fun computeRequestBinding(method: String, path: String, body: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        val bodyHash = md.digest(body)

        md.reset()
        md.update(method.toByteArray(Charsets.UTF_8))
        md.update(path.toByteArray(Charsets.UTF_8))
        return md.digest(bodyHash)
    }

    private fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    @Test
    fun identical_requests_produce_identical_binding_hash() {
        val body1 = """{"pixKey":"test@bank.com","amount":100.00}""".toByteArray(Charsets.UTF_8)
        val body2 = """{"pixKey":"test@bank.com","amount":100.00}""".toByteArray(Charsets.UTF_8)

        val hash1 = computeRequestBinding("POST", "/api/v1/pix/transfer", body1)
        val hash2 = computeRequestBinding("POST", "/api/v1/pix/transfer", body2)

        assertEquals(toHex(hash1), toHex(hash2))
        assertEquals(32, hash1.size)
    }

    @Test
    fun tampering_body_alters_binding_hash() {
        val originalBody = """{"pixKey":"test@bank.com","amount":100.00}""".toByteArray(Charsets.UTF_8)
        val tamperedBody = """{"pixKey":"hacker@evil.com","amount":9999.00}""".toByteArray(Charsets.UTF_8)

        val hashOriginal = computeRequestBinding("POST", "/api/v1/pix/transfer", originalBody)
        val hashTampered = computeRequestBinding("POST", "/api/v1/pix/transfer", tamperedBody)

        assertNotEquals(toHex(hashOriginal), toHex(hashTampered))
    }

    @Test
    fun tampering_url_path_alters_binding_hash() {
        val body = """{"key":"value"}""".toByteArray(Charsets.UTF_8)

        val hash1 = computeRequestBinding("POST", "/api/v1/pix/transfer", body)
        val hash2 = computeRequestBinding("POST", "/api/v1/pix/preview", body)

        assertNotEquals(toHex(hash1), toHex(hash2))
    }

    @Test
    fun tampering_http_method_alters_binding_hash() {
        val body = """{"key":"value"}""".toByteArray(Charsets.UTF_8)

        val hashPost = computeRequestBinding("POST", "/api/v1/resource", body)
        val hashPut = computeRequestBinding("PUT", "/api/v1/resource", body)

        assertNotEquals(toHex(hashPost), toHex(hashPut))
    }
}
