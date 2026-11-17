package com.maigshield.sdk.network

/**
 * Marks a Retrofit service method (or any tagged OkHttp request) as requiring
 * a MaigShield cryptographic proof header (`X-MaigShield-Proof`), removing the
 * need to centrally hardcode endpoint paths in Application.onCreate().
 *
 * Usage with Retrofit:
 * ```kotlin
 * interface PixApi {
 *     @MaigShieldProtected
 *     @POST("/api/v1/pix/transfer")
 *     suspend fun transfer(@Body req: TransferRequest): Response<Unit>
 * }
 * ```
 */
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class MaigShieldProtected
