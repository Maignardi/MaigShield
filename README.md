# 🛡️ MaigShield SDK (`com.maigshield.sdk`)

> **Next-Generation Android Security SDK (Tier-1 Financial Grade RASP + Native Behavioral Biometrics + Anti-Trojan + Hardware Key Attestation)**

[![Android](https://img.shields.io/badge/Platform-Android%207.0%2B%20(API%2024%2B)-green.svg)](https://developer.android.com)
[![Language](https://img.shields.io/badge/Language-Kotlin%20%7C%20C%2B%2B20%20NDK-blue.svg)](https://developer.android.com/ndk)
[![Security](https://img.shields.io/badge/Standard-OWASP%20MASVS--RESILIENCE-red.svg)](https://mas.owasp.org)
[![JitPack](https://jitpack.io/v/Maignardi/MaigShield.svg)](https://jitpack.io/#Maignardi/MaigShield)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](LICENSE)

---

## 🌟 Visão Geral

O **MaigShield** é um SDK Android client-side de defesa cibernética de alta performance projetado para instituições financeiras, fintechs e carteiras de pagamento digital Tier-1. 

Diferente de soluções RASP tradicionais que cometem a ingenuidade de retornar `Boolean` (`isRooted`) ou tentar fechar o app (`exit(0)`) — facilmente contornáveis com uma linha de script no Frida —, o MaigShield opera sob a **Arquitetura Zero-Boolean**. Ele não toma decisões locais no cliente; em vez disso, amarra criptograficamente cada requisição HTTP sensível a um **Envelope Binário de 76 bytes** com **polimorfismo dinâmico de sessão**, assinado via **StrongBox/TEE** e criptografado para o datacenter do banco.

---

## 🏛️ Os 5 Pilares de Defesa Blindada

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
                      │  - Direct Syscalls: sys_openat, sys_read, sys_clock    │
                      │  - IntegrityScanner: /proc/self/maps, TracerPid, ART   │
                      │  - NativeSensors: NDK ASensorManager + Welford         │
                      │  - TokenPacker: 76-byte Polymorphic Telemetry Envelope │
                      └────────────────────────────────────────────────────────┘
```

1. **Zero-Boolean Architecture & Hardware Key Attestation:**
   - Gera o cabeçalho `X-MaigShield-Proof` contendo timestamp do kernel (`CLOCK_MONOTONIC_RAW`), contador monotônico anti-replay, índices comportamentais e as 64 canary flags.
   - **Polimorfismo por Sessão:** As posições das flags no bitmask de 64 bits são embaralhadas a cada requisição via algoritmo de Fisher-Yates com semente $\text{salt} \oplus \text{timestamp} \oplus \text{code\_checksum}$.
   - Criptografia híbrida (AES-256-GCM efêmero + RSA-OAEP SHA-256 do banco) e assinatura em hardware via **StrongBox / TEE** (`EC` P-256 `SHA256withECDSA`).

2. **Núcleo Nativo Blindado em C++20 (`maigshield-native`):**
   - **Syscalls Diretas Inline em Assembly:** Invocações `svc #0` (ARM64) e `syscall` (x86_64) para `openat`, `read`, `close` e `clock_gettime`. Bypass total de hooks na `libc.so`.
   - **Ptrace Sealing:** Bloqueia injeção de debuggers (`sys_ptrace(PTRACE_TRACEME)`).
   - **Inspeção de Kernel e Threads:** Detecta threads internas do Frida (`gum-js-loop`, `pool-frida`), portas abertas (`27042` / `0x69A2`), namespaces de montagem do KernelSU / APatch / Magisk (`/proc/self/mountinfo`), e páginas anônimas `rwxp`.
   - **Timing Check & Checksum Pulverizado:** Medição em nanossegundos contra instrumentação dinâmica (Frida Stalker / eBPF). Checksums de código são inseridos no PRNG do token: se um atacante anular checagens com `NOP`, o token gerado quebra matematicamente.

3. **Escudo Anti-Trojan Bancário & Sequestro de Tela:**
   - Varredura de `AccessibilityManager` detectando troianos (como BrasDex e SharkBot) abusando de permissões de raspagem de tela e cliques sintéticos.
   - Monitoramento de espelhamento via `DisplayManager` / `VirtualDisplay` / `MediaProjection`.
   - Injeção de `FLAG_SECURE` nas janelas e detecção de Tapjacking (`FLAG_WINDOW_IS_OBSCURED`).

4. **Biometria Comportamental Nativa (NDK `ASensorManager`):**
   - Coleta de giroscópio e acelerômetro ativada em thread de alta resolução (50Hz) **apenas durante a janela de toque na tela**.
   - Algoritmo online de Welford calculando variância de micro-tremores em $O(1)$ de memória para gerar `bot_likelihood_score` ($0..255$) e `duress_tremor_index` ($0..255$).

5. **Decepção Cibernética Ativa (Honeypots):**
   - Classes-isca tentadoras para engenharia reversa (`DebugSecurityOverride.disableSslPinning()`, etc.) que acionam silenciosamente o kernel nativo gravando `FLAG_HONEYPOT_TRIGGERED` sem emitir erros ou fechar o app.

---

## 📦 Instalação via Gradle (JitPack)

### 1. Adicione o repositório JitPack no seu `settings.gradle.kts`:
```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

### 2. Adicione a dependência no `build.gradle.kts` do seu módulo de aplicativo:
```kotlin
dependencies {
    implementation("com.github.Maignardi:MaigShield:v1.0.0")
    
    // OkHttp (opcional, caso utilize o Interceptor de rede do MaigShield)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
```

---

## 🚀 Como Usar

### 1. Inicialize o SDK na sua `Application`
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

### 2. Registre o Interceptor no OkHttp
```kotlin
val okHttpClient = OkHttpClient.Builder()
    .addInterceptor(MaigShieldInterceptor()) // Anexa X-MaigShield-Proof em rotas protegidas
    .build()
```

---

## 🔬 App de Demonstração e Diagnóstico Local

O projeto inclui um aplicativo de demonstração (`app/`) com:
- Simulação de transferência Pix protegida com geração de token em tempo real.
- Botão de simulação de ataque Honeypot (Frida Decoy).
- Painel de diagnóstico que descriptografa e desembaralha as canary flags em tempo real usando chave privada de teste.

Para compilar e testar localmente:
```bash
./gradlew :maigshield:assembleDebug :app:assembleDebug
```

---

## 📄 Licença
Distribuído sob a licença Apache 2.0. Veja `LICENSE` para mais detalhes.
