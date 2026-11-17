package com.maigshield.sdk

/**
 * Immutable configuration for MaigShield SDK.
 */
data class MaigShieldConfig(
    val serverPublicKeyPem: String,
    val protectedPaths: List<String> = emptyList(),
    val enableStrongBox: Boolean = true,
    val enforceHardwareAttestation: Boolean = true,
    val enableScreenThreatDetection: Boolean = true,
    val enableTapjackingProtection: Boolean = true,
    val enableBehavioralBiometrics: Boolean = true,
    val allowDebuggable: Boolean = false
) {
    class Builder {
        private var serverPublicKeyPem: String = ""
        private var protectedPaths: List<String> = emptyList()
        private var enableStrongBox: Boolean = true
        private var enforceHardwareAttestation: Boolean = true
        private var enableScreenThreatDetection: Boolean = true
        private var enableTapjackingProtection: Boolean = true
        private var enableBehavioralBiometrics: Boolean = true
        private var allowDebuggable: Boolean = false

        fun setServerPublicKeyPem(pem: String): Builder = apply {
            this.serverPublicKeyPem = pem
        }

        fun setProtectedPaths(paths: List<String>): Builder = apply {
            this.protectedPaths = paths.toList()
        }

        fun setEnableStrongBox(enable: Boolean): Builder = apply {
            this.enableStrongBox = enable
        }

        fun setEnforceHardwareAttestation(enforce: Boolean): Builder = apply {
            this.enforceHardwareAttestation = enforce
        }

        fun setEnableScreenThreatDetection(enable: Boolean): Builder = apply {
            this.enableScreenThreatDetection = enable
        }

        fun setEnableTapjackingProtection(enable: Boolean): Builder = apply {
            this.enableTapjackingProtection = enable
        }

        fun setEnableBehavioralBiometrics(enable: Boolean): Builder = apply {
            this.enableBehavioralBiometrics = enable
        }

        fun setAllowDebuggable(allow: Boolean): Builder = apply {
            this.allowDebuggable = allow
        }

        fun build(): MaigShieldConfig {
            require(serverPublicKeyPem.isNotBlank()) {
                "serverPublicKeyPem must be configured with the Bank's Public Key PEM."
            }
            return MaigShieldConfig(
                serverPublicKeyPem = serverPublicKeyPem,
                protectedPaths = protectedPaths,
                enableStrongBox = enableStrongBox,
                enforceHardwareAttestation = enforceHardwareAttestation,
                enableScreenThreatDetection = enableScreenThreatDetection,
                enableTapjackingProtection = enableTapjackingProtection,
                enableBehavioralBiometrics = enableBehavioralBiometrics,
                allowDebuggable = allowDebuggable
            )
        }
    }
}
