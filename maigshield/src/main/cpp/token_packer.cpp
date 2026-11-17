#include "token_packer.hpp"
#include "syscalls.hpp"
#include "integrity_scanner.hpp"

#include <atomic>
#include <cstring>
#include <algorithm>

namespace maigshield::packer {

static std::atomic<uint64_t> s_counter{1};

void TokenPacker::set_initial_counter(uint64_t initial_val) {
    if (initial_val > 0) {
        s_counter.store(initial_val);
    }
}

uint64_t TokenPacker::get_next_counter() {
    return s_counter.fetch_add(1, std::memory_order_relaxed);
}

void TokenPacker::secure_scrub(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return;
    volatile uint8_t* byte_ptr = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *byte_ptr++ = 0;
    }
}

static uint32_t calculate_crc32(const uint8_t* data, size_t length) noexcept {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

static void generate_bit_permutation(uint64_t seed, uint8_t* out_perm) {
    for (uint8_t i = 0; i < 64; ++i) {
        out_perm[i] = i;
    }

    uint64_t state = (seed != 0) ? seed : 0xDEADBEEFCAFE1234ULL;
    auto prng_next = [&state]() -> uint64_t {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        return state * 0x2545F4914F6CDD1DULL;
    };

    for (int i = 63; i > 0; --i) {
        int j = static_cast<int>(prng_next() % static_cast<uint64_t>(i + 1));
        std::swap(out_perm[i], out_perm[j]);
    }
}

std::vector<uint8_t> TokenPacker::pack_envelope(
    uint64_t raw_flags,
    uint8_t bot_score,
    uint8_t duress_score,
    const uint8_t* binding_hash_32
) {
    TelemetryEnvelope envelope{};
    envelope.magic = 0x4D414947; // "MAIG"
    envelope.version = 0x0001;

    struct timespec ts{};
#if defined(CLOCK_MONOTONIC_RAW)
    clockid_t clk = CLOCK_MONOTONIC_RAW;
#else
    clockid_t clk = CLOCK_MONOTONIC;
#endif
    sys::sys_clock_gettime(clk, &ts);
    envelope.monotonic_timestamp_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
                                      static_cast<uint64_t>(ts.tv_nsec);

    envelope.monotonic_counter = get_next_counter();

    if (binding_hash_32 != nullptr) {
        std::memcpy(envelope.request_binding_hash, binding_hash_32, 32);
    } else {
        std::memset(envelope.request_binding_hash, 0, 32);
    }

    envelope.bot_likelihood_score = bot_score;
    envelope.duress_tremor_index = duress_score;

    // Salt generated combining hardware timing and sequence counter
    envelope.salt = (envelope.monotonic_timestamp_ns << 16) ^ (envelope.monotonic_counter * 0x9E3779B97F4A7C15ULL);

    // Code checksum pulverized into PRNG seed
    uint32_t code_checksum = integrity::IntegrityScanner::calculate_code_checksum();
    uint64_t prng_seed = envelope.salt ^ envelope.monotonic_timestamp_ns ^ static_cast<uint64_t>(code_checksum);

    uint8_t perm[64];
    generate_bit_permutation(prng_seed, perm);

    uint64_t scrambled = 0;
    for (int i = 0; i < 64; ++i) {
        if ((raw_flags >> i) & 1ULL) {
            scrambled |= (1ULL << perm[i]);
        }
    }
    envelope.scrambled_canary_flags = scrambled;

    // Compute integrity CRC32 over the payload prior to crc32 field
    size_t payload_len = sizeof(TelemetryEnvelope) - sizeof(uint32_t);
    envelope.crc32 = calculate_crc32(reinterpret_cast<const uint8_t*>(&envelope), payload_len);

    std::vector<uint8_t> result(sizeof(TelemetryEnvelope));
    std::memcpy(result.data(), &envelope, sizeof(TelemetryEnvelope));

    secure_scrub(&envelope, sizeof(envelope));
    secure_scrub(perm, sizeof(perm));

    return result;
}

uint64_t TokenPacker::unscramble_flags(
    uint64_t scrambled_flags,
    uint64_t salt,
    uint64_t timestamp_ns,
    uint32_t code_checksum
) {
    uint64_t prng_seed = salt ^ timestamp_ns ^ static_cast<uint64_t>(code_checksum);
    uint8_t perm[64];
    generate_bit_permutation(prng_seed, perm);

    uint64_t original = 0;
    for (int i = 0; i < 64; ++i) {
        if ((scrambled_flags >> perm[i]) & 1ULL) {
            original |= (1ULL << i);
        }
    }
    return original;
}

} // namespace maigshield::packer
