package com.maigshield.sdk.network

import com.maigshield.sdk.MaigShield
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import okio.Buffer
import java.io.IOException
import java.lang.reflect.Method

/**
 * OkHttp Interceptor that binds outgoing HTTP requests with cryptographic
 * MaigShield zero-boolean proof tokens.
 *
 * Endpoints are protected automatically when:
 * 1. Their Retrofit method is annotated with `@MaigShieldProtected`, OR
 * 2. Their URL path matches any prefix from `AndroidManifest.xml` `<meta-data>`,
 *    `MaigShield.registerProtectedPaths(...)`, or `MaigShieldConfig.protectedPaths`, OR
 * 3. No protected paths are configured at all (protects all requests by default).
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
        val protectedPaths = maigShield.getEffectiveProtectedPaths()
        val isAnnotated = hasProtectedAnnotation(request)

        val isProtected = isAnnotated ||
            protectedPaths.isEmpty() ||
            protectedPaths.any { path.startsWith(it) }

        if (!isProtected) {
            return chain.proceed(request)
        }

        val bodyBytes = request.body?.let { requestBody ->
            if (requestBody.isOneShot() || requestBody.isDuplex()) {
                null
            } else {
                try {
                    val buffer = Buffer()
                    requestBody.writeTo(buffer)
                    buffer.readByteArray()
                } catch (_: Exception) {
                    null
                }
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

    internal fun hasProtectedAnnotation(request: Request): Boolean {
        return try {
            val invocationClass = Class.forName("retrofit2.Invocation")
            val invocation = request.tag(invocationClass) ?: return false
            val methodGetter: Method = invocationClass.getMethod("method")
            val serviceMethod = methodGetter.invoke(invocation) as? Method ?: return false
            serviceMethod.isAnnotationPresent(MaigShieldProtected::class.java)
        } catch (_: Throwable) {
            false
        }
    }

    companion object {
        const val HEADER_PROOF = "X-MaigShield-Proof"
    }
}
