# MaigShield (`com.maigshield.sdk`)

[![Android](https://img.shields.io/badge/Android-API%2024%2B-3DDC84.svg)](https://developer.android.com)
[![C++20](https://img.shields.io/badge/NDK-C%2B%2B20-00599C.svg)](https://developer.android.com/ndk)
[![OWASP MASVS](https://img.shields.io/badge/OWASP-MASVS--RESILIENCE-red.svg)](https://mas.owasp.org)
[![JitPack](https://jitpack.io/v/Maignardi/MaigShield.svg)](https://jitpack.io/#Maignardi/MaigShield)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Client-side Android RASP, anti-trojan, behavioral biometrics, and hardware attestation library (`com.maigshield.sdk`).

## Design Model: Zero-Boolean Telemetry

Conventional client-side security SDKs expose boolean checks (`isRooted()`, `isFridaDetected()`) or call `exit(0)` locally. In practice, attackers hook those methods with a single Frida snippet or patch the conditional branch.

MaigShield never makes allow/deny decisions on the device and never crashes the host app. On every protected request, the native C++20 core packs a **76-byte binary telemetry envelope** bound to the HTTP request hash, scrambles the 64-bit threat bitmask with a per-session permutation, hybrid-encrypts the envelope to the server's public key, and signs the ciphertext using an Android Keystore **StrongBox / TEE** hardware key. Risk scoring and enforcement happen exclusively on your backend.

---

## Architecture

```
+-------------------------------------------------------------------+
|                        Host Android App                           |
|          Application  |  Activities  |  OkHttpClient              |
+------------------------------+------------------------------------+
                               |
+------------------------------v------------------------------------+
|                  MaigShield Kotlin Layer                          |
|  - MaigShieldInterceptor   : Binds HTTP method, path & body hash  |
|  - ScreenThreatMonitor     : Accessibility & VirtualDisplay scan  |
|  - ShieldWindowCallback    : Tapjacking & synthetic touch capture |
|  - StrongBoxSigner         : RSA-OAEP + AES-256-GCM + ECDSA P-256 |
+------------------------------+------------------------------------+
                               | JNI (JNI_OnLoad / RegisterNatives)
+------------------------------v------------------------------------+
|                Native Core (libmaigshield.so, C++20)              |
|  - syscalls.hpp            : Inline asm svc #0 / syscall wrappers |
|  - integrity_scanner.cpp   : /proc/self/{maps,status,task,mounts} |
|  - native_sensors.cpp      : NDK ASensorManager + Welford stats   |
|  - token_packer.cpp        : 76B envelope + Fisher-Yates bitmask  |
+-------------------------------------------------------------------+
```

---

## Wire Format Specification

### 1. `X-MaigShield-Proof` Header Container

The header value is URL-safe Base64 (no padding, no wrap) encoding the following big-endian container:

| Offset | Field | Size | Description |
| :--- | :--- | :--- | :--- |
| `0` | `protocol_version` | 1 byte | Protocol version (`0x01`). |
| `1` | `encapsulated_key_len` | 2 bytes | Length `K` of RSA-OAEP encrypted AES-256 key. |
| `3` | `encapsulated_key` | `K` bytes | Ephemeral 256-bit AES key encrypted with server RSA public key (`RSA/ECB/OAEPWithSHA-256AndMGF1Padding`). |
| `3+K` | `gcm_iv` | 12 bytes | 96-bit random GCM nonce. |
| `15+K` | `ciphertext_len` | 4 bytes | Length `C` of AES-GCM ciphertext + 16-byte authentication tag. |
| `19+K` | `ciphertext` | `C` bytes | AES-256-GCM encrypted `TelemetryEnvelope` (AAD = `protocol_version || encapsulated_key`). |
| `19+K+C` | `signature_len` | 2 bytes | Length `S` of DER-encoded ECDSA signature. |
| `21+K+C` | `hardware_signature` | `S` bytes | `SHA256withECDSA` over `protocol_version || encapsulated_key || gcm_iv || ciphertext` via StrongBox/TEE. |

### 2. Decrypted `TelemetryEnvelope` (76 bytes, little-endian)

| Offset | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `0` | `magic` | `uint32` | `0x4D414947` (`"MAIG"`). |
| `4` | `version` | `uint16` | Envelope format version (`0x0001`). |
| `6` | `salt` | `uint64` | Per-request salt derived from kernel timestamp and monotonic counter. |
| `14` | `monotonic_timestamp_ns` | `uint64` | `CLOCK_MONOTONIC_RAW` reading via direct syscall. |
| `22` | `monotonic_counter` | `uint64` | Atomic persistent sequence number (anti-replay). |
| `30` | `request_binding_hash` | `uint8[32]` | `SHA-256(HTTP_METHOD || URL_PATH || SHA-256(BODY))`. |
| `62` | `bot_likelihood_score` | `uint8` | Native behavioral bot score (`0..255`). |
| `63` | `duress_tremor_index` | `uint8` | Native tremor/duress index (`0..255`). |
| `64` | `scrambled_canary_flags` | `uint64` | 64-bit threat bitmask permuted via Fisher-Yates (`seed = salt ^ timestamp ^ code_checksum`). |
| `72` | `crc32` | `uint32` | IEEE CRC-32 over bytes `0..71`. |

---

## Canary Bitmask Reference

Before encryption, threat indicators are packed into a 64-bit bitmask and shuffled per request:

| Bit | Constant | Source | Detection |
| :---: | :--- | :--- | :--- |
| `0` | `FLAG_TRACER_PID_ATTACHED` | Native | `TracerPid != 0` in `/proc/self/status` or `PTRACE_TRACEME` failure. |
| `1` | `FLAG_FRIDA_AGENT_MAPPED` | Native | `frida-agent`, `frida-gadget`, or `frida` in `/proc/self/maps`. |
| `2` | `FLAG_XSPOSED_MAPPED` | Native | `xposed`, `edxposed`, or `lsposed` mapped in memory. |
| `3` | `FLAG_SUBSTRATE_MAPPED` | Native | `substrate` / `cydia` mapped in memory. |
| `4` | `FLAG_ANONYMOUS_EXEC_MAPPED` | Native | `rwxp` memory regions excluding legitimate ART JIT caches. |
| `5` | `FLAG_TIMING_OVERHEAD_DETECTED` | Native | Execution latency > 2.5 ms on arithmetic loop (DBI/Stalker/eBPF). |
| `6` | `FLAG_TEXT_CORRUPTION_DETECTED` | Native | Inline trampoline/branch prologue detected on `scan_all`. |
| `7` | `FLAG_HONEYPOT_TRIGGERED` | Native | Any decoy method in `DebugSecurityOverride` invoked. |
| `8` | `FLAG_MAGISK_ZYGISK_MAPPED` | Native | `zygisk`, `libriru`, `magisk`, or `/data/local/tmp` mappings. |
| `9` | `FLAG_ROOT_BINARY_DETECTED` | Native | `su` binaries probed via direct `openat` syscall. |
| `10` | `FLAG_JNI_TABLE_HOOKED` | Native | `JNINativeInterface` pointers outside `libart.so` / `libdvm.so`. |
| `12` | `FLAG_KERNEL_SU_APATCH_MAPPED` | Native | KernelSU / APatch / Magisk entries in `/proc/self/mountinfo`. |
| `13` | `FLAG_FRIDA_PORT_OPEN` | Native | TCP port `27042` (`:69A2`) listening in `/proc/net/tcp`. |
| `14` | `FLAG_FRIDA_THREAD_RUNNING` | Native | `gum-js-loop`, `pool-frida`, `gmain`, `gdbus` via `sys_getdents64`. |
| `16` | `FLAG_ACCESSIBILITY_ABUSE` | Kotlin | Non-system `AccessibilityService` with window retrieval or gesture injection. |
| `17` | `FLAG_SCREEN_MIRRORING` | Kotlin | Active `VirtualDisplay` / presentation / public secondary display. |
| `18` | `FLAG_TAPJACKING_DETECTED` | Kotlin | `FLAG_WINDOW_IS_OBSCURED` or `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`. |
| `19` | `FLAG_SYNTHETIC_TOUCH_DETECTED` | Native / Kotlin | `deviceId <= 0`, zero pressure, or zero contact area on `ACTION_DOWN`. |
| `20` | `FLAG_DURESS_DETECTED` | Native | Native `duress_tremor_index >= 120` via NDK `ASensorManager`. |
| `21` | `FLAG_BOT_DETECTED` | Native | Native `bot_likelihood_score >= 120` via Welford & cadence analysis. |
| `22` | `FLAG_DEBUGGABLE_APP` | Kotlin | `ApplicationInfo.FLAG_DEBUGGABLE` set when `allowDebuggable = false`. |

Bits `32..63` carry the specific honeypot ID mask when bit `7` is set.

---

## Technical Implementation Details

- **Direct Syscalls (`syscalls.hpp`)**: Uses inline assembly (`svc #0` on `arm64-v8a`, `syscall` on `x86_64`) for `openat`, `read`, `close`, `getdents64`, `clock_gettime`, and `ptrace`, avoiding `libc.so` PLT/GOT or inline hooks.
- **Compile-Time String Obfuscation (`obfuscate.hpp`)**: Sensitive proc paths and signatures are XOR-encrypted at compile time with `consteval` position-dependent keys and scrubbed from the stack on scope exit via RAII.
- **Checksums Coupled to PRNG (`token_packer.cpp`)**: `calculate_code_checksum()` hashes the executable `.text` prologue of `IntegrityScanner::scan_all` and XORs it into the Fisher-Yates seed. Patching native checks alters the checksum and invalidates bitmask unscrambling on the server.
- **Native Sensor Biometrics (`native_sensors.cpp`)**: Uses NDK `ASensorManager` and `ASensorEventQueue` (50 Hz) active only between `ACTION_DOWN` and `ACTION_UP`/`ACTION_CANCEL`. Welford's online algorithm tracks acceleration jitter, gyroscope jitter, touch pressure variance, contact area variance, and tap cadence in $O(1)$ memory.
- **Hardened Linker & R8**: Built with `-fvisibility=hidden`, `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Wl,-z,relro,-z,now,-z,noexecstack`, and symbol stripping (`-Wl,-s`). `consumer-rules.pro` preserves JNI bindings and decoy honeypot signatures automatically.

---

## Installation (Gradle / JitPack)

Add JitPack to `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

Add the dependency to your module's `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.github.Maignardi:MaigShield:v1.0.1")

    // Required only if using MaigShieldInterceptor
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
```

---

## Usage

### 1. Initialize in `Application.onCreate()`

```kotlin
class SampleBankApp : Application() {
    override fun onCreate() {
        super.onCreate()

        val config = MaigShieldConfig.Builder()
            .setServerPublicKeyPem("""
                -----BEGIN PUBLIC KEY-----
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
                -----END PUBLIC KEY-----
            """.trimIndent())
            .setProtectedPaths(listOf("/api/v1/pix", "/api/v1/auth", "/api/v1/transfers"))
            .setEnableStrongBox(true)
            .setEnforceHardwareAttestation(true)
            .setEnableScreenThreatDetection(true)
            .setEnableTapjackingProtection(true)
            .setEnableBehavioralBiometrics(true)
            .setAllowDebuggable(false)
            .build()

        MaigShield.initialize(this, config)
    }
}
```

### 2. Attach `MaigShieldInterceptor` to `OkHttpClient`

```kotlin
val client = OkHttpClient.Builder()
    .addInterceptor(MaigShieldInterceptor())
    .build()
```

For manual usage (e.g., Retrofit/Ktor/custom stacks), call `MaigShield.getInstance().mintProofToken(method, path, bodyBytes)` and send the returned string in the `X-MaigShield-Proof` header. To enroll or verify device hardware trust on login/onboarding, export the X.509 attestation chain via `MaigShield.getInstance().getAttestationCertificateChain()`.

---

## Server-Side Verification Flow

1. Base64URL-decode `X-MaigShield-Proof` and parse `protocol_version`, `encapsulated_key`, `gcm_iv`, `ciphertext`, and `hardware_signature`.
2. Verify `hardware_signature` (`SHA256withECDSA`) over `protocol_version || encapsulated_key || gcm_iv || ciphertext` using the device's attested public key.
3. Decrypt `encapsulated_key` with the server's RSA private key (`RSA/ECB/OAEPWithSHA-256AndMGF1Padding`).
4. Decrypt `ciphertext` using AES-256-GCM with AAD = `protocol_version || encapsulated_key`.
5. Validate `magic == 0x4D414947`, verify `crc32`, check `monotonic_counter` > last seen counter for this device, and verify `request_binding_hash` matches `SHA-256(METHOD || URL_PATH || SHA-256(BODY))`.
6. Unscramble `scrambled_canary_flags` using the known build `code_checksum`, `salt`, and `monotonic_timestamp_ns`, then evaluate risk policy using the flags alongside `bot_likelihood_score` and `duress_tremor_index`.

---

## Building & Testing Locally

The repository includes a sample application (`app/`) demonstrating a simulated payment transfer, a honeypot decoy trigger, and a local diagnostic panel that decrypts and unscrambles the envelope using a test keypair.

```bash
./gradlew :maigshield:assembleDebug :app:assembleDebug :maigshield:test
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
