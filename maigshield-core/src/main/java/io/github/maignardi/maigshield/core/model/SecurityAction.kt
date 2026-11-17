package io.github.maignardi.maigshield.core.model

enum class SecurityAction {
    ALLOW,
    MONITOR,
    REQUIRE_REAUTHENTICATION,
    REQUIRE_ADDITIONAL_VERIFICATION,
    RESTRICT_SENSITIVE_OPERATION,
    BLOCK_OPERATION
}
