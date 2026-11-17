package com.maigshield.sdk.network

import com.maigshield.sdk.MaigShield
import okhttp3.Interceptor
import okhttp3.Response
import okio.Buffer
import java.io.IOException

/**
 * OkHttp Interceptor that binds outgoing HTTP requests with cryptographic
 * MaigShield zero-boolean proof tokens.
 */
class MaigShieldInterceptor : Interceptor {

    @Throws(IOException::class)
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val maigShield = try {
            MaigShield.getInstance()
        } catch (_: Exception) {
            // If SDK is not initialized, proceed without proof header
            return chain.proceed(request)
        }

        val path = request.url.encodedPath
        val protectedPaths = maigShield.config.protectedPaths

        // If protectedPaths is specified and current path is not protected, proceed
        val isProtected = protectedPaths.isEmpty() || protectedPaths.any { path.startsWith(it) }
        if (!isProtected) {
            return chain.proceed(request)
        }

        val bodyBytes = request.body?.let { requestBody ->
            try {
                val buffer = Buffer()
                requestBody.writeTo(buffer)
                buffer.readByteArray()
            } catch (_: Exception) {
                null
            }
        }

        val proofToken = maigShield.mintProofToken(
            httpMethod = request.method,
            urlPath = path,
            requestBody = bodyBytes
        )

        val newRequest = request.newBuilder()
            .header(HEADER_PROOF, proofToken)
            .build()

        return chain.proceed(newRequest)
    }

    companion object {
        const val HEADER_PROOF = "X-MaigShield-Proof"
    }
}
