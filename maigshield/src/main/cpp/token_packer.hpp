#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

namespace maigshield::packer {

#pragma pack(push, 1)
struct TelemetryEnvelope {
    uint32_t magic;                    // 0x4D414947 ("MAIG")
    uint16_t version;                  // 0x0001
    uint64_t salt;                     // Session PRNG seed
    uint64_t monotonic_timestamp_ns;   // CLOCK_MONOTONIC_RAW timestamp
    uint64_t monotonic_counter;        // Monotonic sequence counter
    uint8_t  request_binding_hash[32]; // 32-byte request binding hash
    uint8_t  bot_likelihood_score;     // 0..255
    uint8_t  duress_tremor_index;      // 0..255
    uint64_t scrambled_canary_flags;   // Permuted 64-bit canary bitmask
    uint32_t crc32;                    // Envelope integrity checksum
};
#pragma pack(pop)

static_assert(sizeof(TelemetryEnvelope) == 76, "TelemetryEnvelope must be exactly 76 bytes");

class TokenPacker {
public:
    static void set_initial_counter(uint64_t initial_val);
    static uint64_t get_next_counter();

    static std::vector<uint8_t> pack_envelope(
        uint64_t raw_flags,
        uint8_t bot_score,
        uint8_t duress_score,
        const uint8_t* binding_hash_32
    );

    static uint64_t unscramble_flags(
        uint64_t scrambled_flags,
        uint64_t salt,
        uint64_t timestamp_ns,
        uint32_t code_checksum
    );

    static void secure_scrub(void* ptr, size_t size) noexcept;
};

} // namespace maigshield::packer
