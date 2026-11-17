package com.maigshield.sdk

import com.maigshield.sdk.network.MaigShieldInterceptor
import okhttp3.Call
import okhttp3.Connection
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.BufferedSink
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.concurrent.TimeUnit

class MaigShieldInterceptorTest {

    @Test
    fun test_header_constant_matches_protocol_spec() {
        assertEquals("X-MaigShield-Proof", MaigShieldInterceptor.HEADER_PROOF)
    }

    @Test
    fun test_interceptor_passes_through_safely_when_sdk_not_initialized() {
        val interceptor = MaigShieldInterceptor()
        val request = Request.Builder()
            .url("https://api.bank.example/api/v1/pix/transfer")
            .post("{\"amount\":100}".toByteArray().let {
                RequestBody.create("application/json".toMediaType(), it)
            })
            .build()

        var forwardedRequest: Request? = null
        val chain = FakeChain(request) { req ->
            forwardedRequest = req
            Response.Builder()
                .request(req)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body("{}".toResponseBody("application/json".toMediaType()))
                .build()
        }

        val response = interceptor.intercept(chain)
        assertEquals(200, response.code)
        assertNull(forwardedRequest?.header(MaigShieldInterceptor.HEADER_PROOF))
    }

    @Test
    fun test_one_shot_request_body_is_not_consumed_prematurely() {
        var writeCount = 0
        val oneShotBody = object : RequestBody() {
            override fun contentType() = "application/octet-stream".toMediaType()
            override fun isOneShot(): Boolean = true
            override fun writeTo(sink: BufferedSink) {
                writeCount++
                sink.writeUtf8("stream-payload")
            }
        }

        val request = Request.Builder()
            .url("https://api.bank.example/api/v1/upload")
            .post(oneShotBody)
            .build()

        val interceptor = MaigShieldInterceptor()
        val chain = FakeChain(request) { req ->
            Response.Builder()
                .request(req)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body("ok".toResponseBody())
                .build()
        }

        interceptor.intercept(chain)
        assertFalse("One-shot body should not be drained by interceptor", writeCount > 0)
    }

    private class FakeChain(
        private val initialRequest: Request,
        private val handler: (Request) -> Response
    ) : Interceptor.Chain {
        override fun request(): Request = initialRequest
        override fun proceed(request: Request): Response = handler(request)
        override fun connection(): Connection? = null
        override fun call(): Call = throw UnsupportedOperationException()
        override fun connectTimeoutMillis(): Int = 10_000
        override fun withConnectTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
        override fun readTimeoutMillis(): Int = 10_000
        override fun withReadTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
        override fun writeTimeoutMillis(): Int = 10_000
        override fun withWriteTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
    }
}
