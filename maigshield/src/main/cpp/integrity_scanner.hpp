#pragma once

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <jni.h>

namespace maigshield::integrity {

// 64-bit Threat Canary Indicators
constexpr uint64_t FLAG_TRACER_PID_ATTACHED      = 1ULL << 0;
constexpr uint64_t FLAG_FRIDA_AGENT_MAPPED       = 1ULL << 1;
constexpr uint64_t FLAG_XSPOSED_MAPPED           = 1ULL << 2;
constexpr uint64_t FLAG_SUBSTRATE_MAPPED         = 1ULL << 3;
constexpr uint64_t FLAG_ANONYMOUS_EXEC_MAPPED    = 1ULL << 4;
constexpr uint64_t FLAG_TIMING_OVERHEAD_DETECTED = 1ULL << 5;
constexpr uint64_t FLAG_TEXT_CORRUPTION_DETECTED = 1ULL << 6;
constexpr uint64_t FLAG_HONEYPOT_TRIGGERED       = 1ULL << 7;
constexpr uint64_t FLAG_MAGISK_ZYGISK_MAPPED     = 1ULL << 8;
constexpr uint64_t FLAG_ROOT_BINARY_DETECTED     = 1ULL << 9;
constexpr uint64_t FLAG_JNI_TABLE_HOOKED         = 1ULL << 10;
constexpr uint64_t FLAG_ART_HOOK_DETECTED        = 1ULL << 11;
constexpr uint64_t FLAG_KERNEL_SU_APATCH_MAPPED  = 1ULL << 12;
constexpr uint64_t FLAG_FRIDA_PORT_OPEN          = 1ULL << 13;
constexpr uint64_t FLAG_FRIDA_THREAD_RUNNING     = 1ULL << 14;

// UI & Environmental Threat Flags (propagated from Java monitor)
constexpr uint64_t FLAG_ACCESSIBILITY_ABUSE      = 1ULL << 16;
constexpr uint64_t FLAG_SCREEN_MIRRORING         = 1ULL << 17;
constexpr uint64_t FLAG_TAPJACKING_DETECTED      = 1ULL << 18;
constexpr uint64_t FLAG_SYNTHETIC_TOUCH_DETECTED = 1ULL << 19;
constexpr uint64_t FLAG_DURESS_DETECTED          = 1ULL << 20;
constexpr uint64_t FLAG_BOT_DETECTED             = 1ULL << 21;
constexpr uint64_t FLAG_DEBUGGABLE_APP           = 1ULL << 22;

class IntegrityScanner {
public:
    static uint64_t scan_all(JNIEnv* env);
    static bool check_tracer_pid();
    static bool check_ptrace_seal();
    static uint64_t scan_proc_maps();
    static bool scan_threads();
    static bool scan_mounts();
    static bool scan_tcp_ports();
    static bool check_timing_anomalies();
    static bool verify_text_checksum();
    static bool verify_jni_env(JNIEnv* env);
    static bool check_root_binaries();

    static void trigger_honeypot(uint32_t honeypot_id = 0);
    static bool is_honeypot_triggered();
    static uint64_t get_honeypot_mask();

    // Checksum of critical executable code sections for pulverization
    static uint32_t calculate_code_checksum();

private:
    static inline std::atomic<uint64_t> s_honeypot_state{0};
};

} // namespace maigshield::integrity
