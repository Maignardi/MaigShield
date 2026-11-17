# 🛡️ MaigShield SDK (`com.maigshield.sdk`)

> **Next-Generation Android Security SDK (Tier-1 Financial Grade RASP + Native Behavioral Biometrics + Anti-Trojan + Hardware Key Attestation)**

[![Android](https://img.shields.io/badge/Platform-Android%207.0%2B%20(API%2024%2B)-green.svg)](https://developer.android.com)
[![Language](https://img.shields.io/badge/Language-Kotlin%20%7C%20C%2B%2B20%20NDK-blue.svg)](https://developer.android.com/ndk)
[![Security](https://img.shields.io/badge/Standard-OWASP%20MASVS--RESILIENCE-red.svg)](https://mas.owasp.org)
[![JitPack](https://jitpack.io/v/Maignardi/MaigShield.svg)](https://jitpack.io/#Maignardi/MaigShield)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](LICENSE)

---

## 🌟 Overview

**MaigShield** is a high-performance client-side Android cyber-defense SDK engineered for Tier-1 financial institutions, fintechs, and digital payment wallets.

Unlike traditional RASP libraries that naively return `Boolean` flags (`isRooted`, `isHooked`) or attempt to terminate the app (`exit(0)`)—which are trivially bypassed with a single-line Frida script—MaigShield operates under a **Zero-Boolean Architecture**. It never enforces local allow/deny decisions on the client; instead, it cryptographically binds every sensitive HTTP request to a **76-byte Binary Telemetry Envelope** with **per-session bitmask polymorphism**, signed in hardware via **StrongBox/TEE** and hybrid-encrypted for the bank's datacenter.

---

## 🏛️ The 5 Armored Defense Pillars

```
                      ┌────────────────────────────────────────────────────────┐
                      │              Android Application Layer                 │
                      │  (SampleBankApp / MainActivity / OkHttp Interceptor)   │
                      └───────────────────────────┬────────────────────────────┘
                                                  │
                      ┌───────────────────────────▼────────────────────────────┐
                      │             MaigShield SDK (Client Core)               │
                      │  - ShieldWindowCallback (Tapjacking & Synthetic Touch) │
                      │  - ScreenThreatMonitor (Accessibility & VirtualDisplay)│
                      │  - StrongBoxSigner (Key Attestation & Hybrid Crypto)   │
                      └───────────────────────────┬────────────────────────────┘
                                                  │ (JNI_OnLoad / RegisterNatives)
                      ┌───────────────────────────▼────────────────────────────┐
                      │        Native C++20 Core (libmaigshield.so)            │
                      │  - Direct Syscalls: openat, read, getdents64, ptrace   │
                      │  - IntegrityScanner: /proc/self/maps, TracerPid, ART   │
                      │  - NativeSensors: NDK ASensorManager + Welford         │
                      │  - TokenPacker: 76-byte Polymorphic Telemetry Envelope │
                      └────────────────────────────────────────────────────────┘
```

1. **Zero-Boolean Architecture, Hybrid Cryptography & Hardware Key Attestation:**
   - Emits the `X-MaigShield-Proof` header containing a kernel monotonic timestamp (`CLOCK_MONOTONIC_RAW`), persistent anti-replay sequence counter, SHA-256 request binding (`METHOD + URL_PATH + SHA256(BODY)`), behavioral indices, and 64 canary threat flags.
   - **Per-Session Bitmask Polymorphism:** Canary bit positions within the 64-bit mask are shuffled on every request using a Fisher-Yates permutation seeded with $\text{salt} \oplus \text{timestamp} \oplus \text{code\_checksum}$.
   - **AEAD Hybrid Encryption & StrongBox Signing:** Ephemeral AES-256-GCM (with AAD binding protocol version and encapsulated key) + RSA-OAEP SHA-256 key encapsulation + Android Keystore **StrongBox / TEE** (`EC` P-256 `SHA256withECDSA` with `setAttestationChallenge`).

2. **Hardened C++20 Native Core (`maigshield-native`):**
   - **Direct Inline Assembly Syscalls:** Raw `svc #0` (ARM64) and `syscall` (x86_64) wrappers for `openat`, `read`, `close`, `getdents64`, `clock_gettime`, and `ptrace`—completely bypassing `libc.so` hooks.
   - **Compile-Time Rolling String Obfuscation:** C++20 `consteval` position-dependent XOR cipher (`OBFUSCATE_STACK`) with RAII stack memory scrubbing.
   - **Kernel, Thread & ART Inspection:** Detects Frida threads (`gum-js-loop`, `pool-frida`, `gmain`, `gdbus`), open Frida ports (`27042` / `0x69A2`), KernelSU / APatch / Magisk / Zygisk mounts, anonymous `rwxp` memory pages (excluding legitimate ART JIT caches), and `JNINativeInterface` pointer table hijacking (`FindClass`, `GetMethodID`, `RegisterNatives`, `CallObjectMethodV`, `GetByteArrayElements`).
   - **Timing Side-Channel & Pulverized Checksums:** Nanosecond latency checks against Frida Stalker / DBI / eBPF, plus executable `.text` checksums mixed directly into the token PRNG seed—if an attacker NOPs out a check, the generated token mathematically breaks.

3. **Anti-Banking Trojan & Screen Hijacking Shield:**
   - Scans `AccessibilityManager` for third-party non-system services abusing `CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT` or `CAPABILITY_CAN_PERFORM_GESTURES`.
   - Monitors `DisplayManager` / `VirtualDisplay` / `MediaProjection` for unauthorized screen mirroring and applies `FLAG_SECURE` to protected windows.
   - Automatically injects `ShieldWindowCallback` across all Activities to flag `FLAG_WINDOW_IS_OBSCURED` / `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` (Tapjacking) and synthetic touches.

4. **Native Behavioral Biometrics & Duress Detection (NDK `ASensorManager`):**
   - Samples accelerometer and gyroscope directly in C++ via NDK `ASensorManager` / `ASensorEventQueue` (50 Hz) **only during active touch windows** for minimal battery overhead and immunity to Java-layer hooks.
   - Uses Welford's online algorithm in $O(1)$ memory to compute micro-tremor variance, touch pressure variance, and tap cadence regularity, producing `bot_likelihood_score` (`0..255`) and `duress_tremor_index` (`0..255`).

5. **Active Cyber Deception (Internal Honeypots):**
   - High-value decoy classes and methods (`DebugSecurityOverride.disableSslPinning()`, `bypassRootChecks()`, `exportMasterSeed()`, `setDebugMode()`, `allowAllCertificates()`) that silently record `FLAG_HONEYPOT_TRIGGERED` in atomic native memory without throwing errors or crashing.

---

## 📦 Installation via Gradle (JitPack)

### 1. Add the JitPack repository to `settings.gradle.kts`:
```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

### 2. Add the dependency to your app module's `build.gradle.kts`:
```kotlin
dependencies {
    implementation("com.github.Maignardi:MaigShield:v1.0.0")

    // OkHttp (optional, required if using MaigShieldInterceptor)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
```

---

## 🚀 Quick Start

### 1. Initialize the SDK in your `Application` class
```kotlin
class SampleBankApp : Application() {
    override fun onCreate() {
        super.onCreate()

        val config = MaigShieldConfig.Builder()
            .setServerPublicKeyPem("""
                -----BEGIN PUBLIC KEY-----
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy0...
                -----END PUBLIC KEY-----
            """.trimIndent())
            .setProtectedPaths(listOf("/api/v1/pix", "/api/v1/auth", "/api/v1/transfers"))
            .setEnableStrongBox(true)
            .setEnforceHardwareAttestation(true)
            .setEnableScreenThreatDetection(true)
            .setEnableTapjackingProtection(true)
            .setEnableBehavioralBiometrics(true)
            .build()

        MaigShield.initialize(this, config)
    }
}
```

### 2. Attach the OkHttp Interceptor
```kotlin
val okHttpClient = OkHttpClient.Builder()
    .addInterceptor(MaigShieldInterceptor()) // Attaches X-MaigShield-Proof on protected paths
    .build()
```

---

## 🔬 Sample App & Local Diagnostics

The repository includes a sample application (`app/`) featuring:
- A simulated payment transfer flow generating real-time `X-MaigShield-Proof` tokens.
- An interactive Honeypot simulation button (mimicking a Frida decoy hook).
- A local Telemetry & Diagnostics Panel that decrypts and unscrambles the 64-bit canary bitmask in real time using a test RSA private key.

To build the library, sample app, and run all unit tests locally:
```bash
./gradlew :maigshield:assembleDebug :app:assembleDebug :maigshield:test
```

---

## 📄 License
Distributed under the Apache 2.0 License. See `LICENSE` for details.
