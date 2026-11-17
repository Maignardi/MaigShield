#pragma once

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <cstdint>
#include <sys/ptrace.h>

#if defined(__aarch64__)
    #define SYS_OPENAT_NR        56
    #define SYS_CLOSE_NR         57
    #define SYS_READ_NR          63
    #define SYS_CLOCK_GETTIME_NR 113
    #define SYS_PTRACE_NR        117
#elif defined(__x86_64__)
    #define SYS_READ_NR          0
    #define SYS_CLOSE_NR         3
    #define SYS_PTRACE_NR        101
    #define SYS_CLOCK_GETTIME_NR 228
    #define SYS_OPENAT_NR        257
#endif

namespace maigshield::sys {

inline long sys_openat(int dirfd, const char* pathname, int flags, mode_t mode) noexcept {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = SYS_OPENAT_NR;
    register long x0 __asm__("x0") = dirfd;
    register long x1 __asm__("x1") = reinterpret_cast<long>(pathname);
    register long x2 __asm__("x2") = flags;
    register long x3 __asm__("x3") = static_cast<long>(mode);
    __asm__ volatile (
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
        : "memory", "cc"
    );
    return x0;
#elif defined(__x86_64__)
    long ret;
    register long r10 __asm__("r10") = static_cast<long>(mode);
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(SYS_OPENAT_NR), "D"(dirfd), "S"(pathname), "d"(flags), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
#else
    return ::openat(dirfd, pathname, flags, mode);
#endif
}

inline long sys_read(int fd, void* buf, size_t count) noexcept {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = SYS_READ_NR;
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = reinterpret_cast<long>(buf);
    register long x2 __asm__("x2") = static_cast<long>(count);
    __asm__ volatile (
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2)
        : "memory", "cc"
    );
    return x0;
#elif defined(__x86_64__)
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(SYS_READ_NR), "D"(fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
#else
    return ::read(fd, buf, count);
#endif
}

inline long sys_close(int fd) noexcept {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = SYS_CLOSE_NR;
    register long x0 __asm__("x0") = fd;
    __asm__ volatile (
        "svc #0"
        : "+r"(x0)
        : "r"(x8)
        : "memory", "cc"
    );
    return x0;
#elif defined(__x86_64__)
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(SYS_CLOSE_NR), "D"(fd)
        : "rcx", "r11", "memory"
    );
    return ret;
#else
    return ::close(fd);
#endif
}

inline long sys_clock_gettime(clockid_t clk_id, struct timespec* tp) noexcept {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = SYS_CLOCK_GETTIME_NR;
    register long x0 __asm__("x0") = clk_id;
    register long x1 __asm__("x1") = reinterpret_cast<long>(tp);
    __asm__ volatile (
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1)
        : "memory", "cc"
    );
    return x0;
#elif defined(__x86_64__)
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(SYS_CLOCK_GETTIME_NR), "D"(clk_id), "S"(tp)
        : "rcx", "r11", "memory"
    );
    return ret;
#else
    return ::clock_gettime(clk_id, tp);
#endif
}

inline long sys_ptrace(long request, pid_t pid, void* addr, void* data) noexcept {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = SYS_PTRACE_NR;
    register long x0 __asm__("x0") = request;
    register long x1 __asm__("x1") = static_cast<long>(pid);
    register long x2 __asm__("x2") = reinterpret_cast<long>(addr);
    register long x3 __asm__("x3") = reinterpret_cast<long>(data);
    __asm__ volatile (
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
        : "memory", "cc"
    );
    return x0;
#elif defined(__x86_64__)
    long ret;
    register long r10 __asm__("r10") = reinterpret_cast<long>(data);
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(SYS_PTRACE_NR), "D"(request), "S"(static_cast<long>(pid)), "d"(addr), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
#else
    return ::ptrace(static_cast<__ptrace_request>(request), pid, addr, data);
#endif
}

} // namespace maigshield::sys
