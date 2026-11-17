#include "integrity_scanner.hpp"
#include "syscalls.hpp"
#include "obfuscate.hpp"

#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/types.h>

namespace maigshield::integrity {

void IntegrityScanner::trigger_honeypot(uint32_t honeypot_id) {
    if (honeypot_id < 64) {
        s_honeypot_state.fetch_or(1ULL << honeypot_id, std::memory_order_relaxed);
    } else {
        s_honeypot_state.fetch_or(1ULL, std::memory_order_relaxed);
    }
}

bool IntegrityScanner::is_honeypot_triggered() {
    return s_honeypot_state.load(std::memory_order_relaxed) != 0;
}

uint64_t IntegrityScanner::get_honeypot_mask() {
    return s_honeypot_state.load(std::memory_order_relaxed);
}

bool IntegrityScanner::check_ptrace_seal() {
    // On Android (API 26+), SELinux/seccomp blocks PTRACE_TRACEME for untrusted_app
    // with -EACCES/-EPERM even on clean devices. Instead, verify kernel tracing state
    // via /proc/self/wchan (returns "ptrace_stop" when stopped by a tracer).
    OBFUSCATE_STACK(path_wchan, "/proc/self/wchan");
    long fd = sys::sys_openat(AT_FDCWD, path_wchan.c_str(), O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }

    char wchan_buf[128];
    long n = sys::sys_read(static_cast<int>(fd), wchan_buf, sizeof(wchan_buf) - 1);
    sys::sys_close(static_cast<int>(fd));
    if (n <= 0) {
        return false;
    }
    wchan_buf[n] = '\0';

    OBFUSCATE_STACK(kw_ptrace, "ptrace_stop");
    return strstr(wchan_buf, kw_ptrace.c_str()) != nullptr;
}

bool IntegrityScanner::check_tracer_pid() {
    OBFUSCATE_STACK(path_status, "/proc/self/status");
    long fd = sys::sys_openat(AT_FDCWD, path_status.c_str(), O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }

    char buffer[2048];
    long bytes_read = sys::sys_read(static_cast<int>(fd), buffer, sizeof(buffer) - 1);
    sys::sys_close(static_cast<int>(fd));

    if (bytes_read <= 0) {
        return false;
    }
    buffer[bytes_read] = '\0';

    OBFUSCATE_STACK(tracer_prefix, "TracerPid:\t");
    char* line = strstr(buffer, tracer_prefix.c_str());
    if (!line) {
        return false;
    }

    char* pid_str = line + tracer_prefix.size();
    while (*pid_str == ' ' || *pid_str == '\t') {
        pid_str++;
    }

    long pid = 0;
    while (*pid_str >= '0' && *pid_str <= '9') {
        pid = (pid * 10) + (*pid_str - '0');
        pid_str++;
    }

    return pid > 0;
}

uint64_t IntegrityScanner::scan_proc_maps() {
    uint64_t flags = 0;
    OBFUSCATE_STACK(path_maps, "/proc/self/maps");
    long fd = sys::sys_openat(AT_FDCWD, path_maps.c_str(), O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return flags;
    }

    char chunk[4096];
    char line[1024];
    size_t line_pos = 0;
    long n = 0;

    OBFUSCATE_STACK(kw_frida_agent, "frida-agent");
    OBFUSCATE_STACK(kw_frida_gadget, "frida-gadget");
    OBFUSCATE_STACK(kw_frida, "frida");
    OBFUSCATE_STACK(kw_xposed, "xposed");
    OBFUSCATE_STACK(kw_edxposed, "edxposed");
    OBFUSCATE_STACK(kw_lsposed, "lsposed");
    OBFUSCATE_STACK(kw_substrate, "substrate");
    OBFUSCATE_STACK(kw_cydia, "cydia");
    OBFUSCATE_STACK(kw_zygisk, "zygisk");
    OBFUSCATE_STACK(kw_riru, "libriru");
    OBFUSCATE_STACK(kw_magisk, "magisk");
    OBFUSCATE_STACK(kw_tmp, "/data/local/tmp");
    OBFUSCATE_STACK(kw_rwxp, "rwxp");
    OBFUSCATE_STACK(kw_jit_cache, "jit-cache");
    OBFUSCATE_STACK(kw_dalvik_jit, "dalvik-jit-code-cache");
    OBFUSCATE_STACK(kw_zygote_jit, "jit-zygote-cache");

    while ((n = sys::sys_read(static_cast<int>(fd), chunk, sizeof(chunk))) > 0) {
        for (long i = 0; i < n; ++i) {
            char c = chunk[i];
            if (c == '\n' || line_pos >= sizeof(line) - 1) {
                line[line_pos] = '\0';

                if (strstr(line, kw_frida_agent.c_str()) ||
                    strstr(line, kw_frida_gadget.c_str()) ||
                    strstr(line, kw_frida.c_str())) {
                    flags |= FLAG_FRIDA_AGENT_MAPPED;
                }
                if (strstr(line, kw_xposed.c_str()) ||
                    strstr(line, kw_edxposed.c_str()) ||
                    strstr(line, kw_lsposed.c_str())) {
                    flags |= FLAG_XSPOSED_MAPPED;
                }
                if (strstr(line, kw_substrate.c_str()) ||
                    strstr(line, kw_cydia.c_str())) {
                    flags |= FLAG_SUBSTRATE_MAPPED;
                }
                if (strstr(line, kw_zygisk.c_str()) ||
                    strstr(line, kw_riru.c_str()) ||
                    strstr(line, kw_magisk.c_str()) ||
                    strstr(line, kw_tmp.c_str())) {
                    flags |= FLAG_MAGISK_ZYGISK_MAPPED;
                }
                if (strstr(line, kw_rwxp.c_str()) != nullptr &&
                    strstr(line, kw_jit_cache.c_str()) == nullptr &&
                    strstr(line, kw_dalvik_jit.c_str()) == nullptr &&
                    strstr(line, kw_zygote_jit.c_str()) == nullptr) {
                    flags |= FLAG_ANONYMOUS_EXEC_MAPPED;
                }

                line_pos = 0;
            } else {
                line[line_pos++] = c;
            }
        }
    }

    sys::sys_close(static_cast<int>(fd));
    return flags;
}

bool IntegrityScanner::scan_threads() {
    OBFUSCATE_STACK(path_task, "/proc/self/task");
    long dir_fd = sys::sys_openat(AT_FDCWD, path_task.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (dir_fd < 0) {
        return false;
    }

    OBFUSCATE_STACK(kw_gum, "gum-js-loop");
    OBFUSCATE_STACK(kw_gmain, "gmain");
    OBFUSCATE_STACK(kw_pool, "pool-frida");
    OBFUSCATE_STACK(kw_gdbus, "gdbus");
    OBFUSCATE_STACK(kw_frida, "frida");
    OBFUSCATE_STACK(comm_suffix, "/comm");

    char dir_buf[4096];
    bool detected = false;
    long nread = 0;

    while (!detected && (nread = sys::sys_getdents64(static_cast<int>(dir_fd), dir_buf, sizeof(dir_buf))) > 0) {
        long bpos = 0;
        while (bpos < nread) {
            const auto* d = reinterpret_cast<const sys::linux_dirent64*>(dir_buf + bpos);
            if (d->d_reclen == 0) break;

            if (d->d_name[0] != '.') {
                char comm_path[128];
                size_t prefix_len = path_task.size();
                size_t name_len = strnlen(d->d_name, 32);
                size_t suffix_len = comm_suffix.size();

                if (prefix_len + 1 + name_len + suffix_len < sizeof(comm_path)) {
                    memcpy(comm_path, path_task.c_str(), prefix_len);
                    comm_path[prefix_len] = '/';
                    memcpy(comm_path + prefix_len + 1, d->d_name, name_len);
                    memcpy(comm_path + prefix_len + 1 + name_len, comm_suffix.c_str(), suffix_len);
                    comm_path[prefix_len + 1 + name_len + suffix_len] = '\0';

                    long fd = sys::sys_openat(AT_FDCWD, comm_path, O_RDONLY | O_CLOEXEC, 0);
                    if (fd >= 0) {
                        char comm_name[64];
                        long n = sys::sys_read(static_cast<int>(fd), comm_name, sizeof(comm_name) - 1);
                        sys::sys_close(static_cast<int>(fd));

                        if (n > 0) {
                            comm_name[n] = '\0';
                            if (strstr(comm_name, kw_gum.c_str()) ||
                                strstr(comm_name, kw_gmain.c_str()) ||
                                strstr(comm_name, kw_pool.c_str()) ||
                                strstr(comm_name, kw_gdbus.c_str()) ||
                                strstr(comm_name, kw_frida.c_str())) {
                                detected = true;
                                break;
                            }
                        }
                    }
                }
            }
            bpos += d->d_reclen;
        }
    }

    sys::sys_close(static_cast<int>(dir_fd));
    return detected;
}

bool IntegrityScanner::scan_mounts() {
    OBFUSCATE_STACK(path_mounts, "/proc/self/mountinfo");
    long fd = sys::sys_openat(AT_FDCWD, path_mounts.c_str(), O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }

    OBFUSCATE_STACK(kw_magisk, "magisk");
    OBFUSCATE_STACK(kw_core, "core/mirror");
    OBFUSCATE_STACK(kw_ksu, "kernel_su");
    OBFUSCATE_STACK(kw_kernelsu, "kernelsu");
    OBFUSCATE_STACK(kw_ksu_slash, "/ksu");
    OBFUSCATE_STACK(kw_apatch, "apatch");

    char chunk[2048];
    char line[1024];
    size_t line_pos = 0;
    long n = 0;
    bool detected = false;

    while (!detected && (n = sys::sys_read(static_cast<int>(fd), chunk, sizeof(chunk))) > 0) {
        for (long i = 0; i < n; ++i) {
            char c = chunk[i];
            if (c == '\n' || line_pos >= sizeof(line) - 1) {
                line[line_pos] = '\0';
                if (strstr(line, kw_magisk.c_str()) ||
                    strstr(line, kw_core.c_str()) ||
                    strstr(line, kw_ksu.c_str()) ||
                    strstr(line, kw_kernelsu.c_str()) ||
                    strstr(line, kw_ksu_slash.c_str()) ||
                    strstr(line, kw_apatch.c_str())) {
                    detected = true;
                    break;
                }
                line_pos = 0;
            } else {
                line[line_pos++] = c;
            }
        }
    }

    if (!detected && line_pos > 0) {
        line[line_pos] = '\0';
        if (strstr(line, kw_magisk.c_str()) ||
            strstr(line, kw_core.c_str()) ||
            strstr(line, kw_ksu.c_str()) ||
            strstr(line, kw_kernelsu.c_str()) ||
            strstr(line, kw_ksu_slash.c_str()) ||
            strstr(line, kw_apatch.c_str())) {
            detected = true;
        }
    }

    sys::sys_close(static_cast<int>(fd));
    return detected;
}

bool IntegrityScanner::scan_tcp_ports() {
    OBFUSCATE_STACK(path_tcp, "/proc/net/tcp");
    long fd = sys::sys_openat(AT_FDCWD, path_tcp.c_str(), O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }

    // Default Frida server/gadget listening port 27042 is 0x69A2 in hex
    OBFUSCATE_STACK(frida_port_hex, ":69A2");

    char buffer[2048];
    long n = 0;
    bool detected = false;

    while ((n = sys::sys_read(static_cast<int>(fd), buffer, sizeof(buffer) - 1)) > 0) {
        buffer[n] = '\0';
        if (strstr(buffer, frida_port_hex.c_str()) != nullptr) {
            detected = true;
            break;
        }
    }

    sys::sys_close(static_cast<int>(fd));
    return detected;
}

bool IntegrityScanner::check_timing_anomalies() {
    struct timespec ts_start{}, ts_end{};

#if defined(CLOCK_MONOTONIC_RAW)
    clockid_t clk = CLOCK_MONOTONIC_RAW;
#else
    clockid_t clk = CLOCK_MONOTONIC;
#endif

    if (sys::sys_clock_gettime(clk, &ts_start) != 0) {
        return false;
    }

    volatile uint64_t accum = 0x123456789ABCDEF0ULL;
    for (int i = 0; i < 4000; ++i) {
        accum = (accum ^ static_cast<uint64_t>(i)) * 6364136223846793005ULL + 1442695040888963407ULL;
    }

    if (sys::sys_clock_gettime(clk, &ts_end) != 0) {
        return false;
    }

    uint64_t elapsed_ns = static_cast<uint64_t>((ts_end.tv_sec - ts_start.tv_sec) * 1000000000ULL +
                                                (ts_end.tv_nsec - ts_start.tv_nsec));

    // Calibrated threshold: ~15-50us natively vs >2.5ms under Frida Stalker/DBI instrumentation
    return (elapsed_ns > 2500000ULL) && (accum != 0);
}

static uint32_t fnv1a_32(const uint8_t* data, size_t length) {
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

bool IntegrityScanner::verify_text_checksum() {
    Dl_info dl_info{};
    if (dladdr(reinterpret_cast<void*>(&IntegrityScanner::scan_all), &dl_info) == 0) {
        return false;
    }

    if (!dl_info.dli_saddr) {
        return false;
    }

    const auto* code_ptr = reinterpret_cast<const uint8_t*>(dl_info.dli_saddr);

#if defined(__aarch64__)
    uint32_t first_insn = *reinterpret_cast<const uint32_t*>(code_ptr);
    if ((first_insn & 0xFF00001F) == 0x58000010 || first_insn == 0xD61F0200 || first_insn == 0xD61F0220) {
        return true;
    }
#elif defined(__x86_64__)
    uint8_t first_byte = code_ptr[0];
    if (first_byte == 0xE9 || (first_byte == 0xFF && (code_ptr[1] & 0x38) == 0x20)) {
        return true;
    }
#endif

    uint32_t hash = fnv1a_32(code_ptr, 64);
    return hash == 0;
}

bool IntegrityScanner::verify_jni_env(JNIEnv* env) {
    if (!env || !env->functions) {
        return true;
    }

    const void* jni_ptrs[] = {
        reinterpret_cast<const void*>(env->functions->FindClass),
        reinterpret_cast<const void*>(env->functions->GetMethodID),
        reinterpret_cast<const void*>(env->functions->RegisterNatives),
        reinterpret_cast<const void*>(env->functions->CallObjectMethodV),
        reinterpret_cast<const void*>(env->functions->GetByteArrayElements)
    };

    OBFUSCATE_STACK(libart_name, "libart.so");
    OBFUSCATE_STACK(libdvm_name, "libdvm.so");

    for (const void* ptr : jni_ptrs) {
        if (!ptr) {
            return true;
        }
        Dl_info info{};
        if (dladdr(ptr, &info) == 0 || !info.dli_fname) {
            return true;
        }
        if (strstr(info.dli_fname, libart_name.c_str()) == nullptr &&
            strstr(info.dli_fname, libdvm_name.c_str()) == nullptr) {
            return true;
        }
    }

    return false;
}

bool IntegrityScanner::check_root_binaries() {
    const char* root_paths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su"
    };

    for (const char* path : root_paths) {
        long fd = sys::sys_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            sys::sys_close(static_cast<int>(fd));
            return true;
        }
    }
    return false;
}

uint32_t IntegrityScanner::calculate_code_checksum() {
    Dl_info dl_info{};
    if (dladdr(reinterpret_cast<void*>(&IntegrityScanner::scan_all), &dl_info) != 0 && dl_info.dli_saddr) {
        return fnv1a_32(reinterpret_cast<const uint8_t*>(dl_info.dli_saddr), 128);
    }
    return 0x9E3779B9;
}

uint64_t IntegrityScanner::scan_all(JNIEnv* env) {
    uint64_t mask = 0;

    if (check_tracer_pid() || check_ptrace_seal()) {
        mask |= FLAG_TRACER_PID_ATTACHED;
    }

    mask |= scan_proc_maps();

    if (scan_threads()) {
        mask |= FLAG_FRIDA_THREAD_RUNNING;
    }

    if (scan_mounts()) {
        mask |= FLAG_KERNEL_SU_APATCH_MAPPED;
    }

    if (scan_tcp_ports()) {
        mask |= FLAG_FRIDA_PORT_OPEN;
    }

    if (check_timing_anomalies()) {
        mask |= FLAG_TIMING_OVERHEAD_DETECTED;
    }

    if (verify_text_checksum()) {
        mask |= FLAG_TEXT_CORRUPTION_DETECTED;
    }

    if (verify_jni_env(env)) {
        mask |= FLAG_JNI_TABLE_HOOKED;
    }

    if (check_root_binaries()) {
        mask |= FLAG_ROOT_BINARY_DETECTED;
    }

    if (is_honeypot_triggered()) {
        mask |= FLAG_HONEYPOT_TRIGGERED;
        mask |= (get_honeypot_mask() << 32);
    }

    return mask;
}

} // namespace maigshield::integrity
