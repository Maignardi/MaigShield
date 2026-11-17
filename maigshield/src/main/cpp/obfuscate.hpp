#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <string>
#include <utility>

namespace maigshield::crypto {

template <size_t N>
struct ObfuscatedString {
    std::array<char, N> buffer{};
    uint8_t key{0};

    consteval explicit ObfuscatedString(const char (&str)[N], uint8_t xor_key) noexcept : key(xor_key) {
        for (size_t i = 0; i < N; ++i) {
            uint8_t k = static_cast<uint8_t>(key + (i * 7U));
            buffer[i] = static_cast<char>(static_cast<uint8_t>(str[i]) ^ k);
        }
    }

    void decrypt(char* out) const noexcept {
        for (size_t i = 0; i < N; ++i) {
            uint8_t k = static_cast<uint8_t>(key + (i * 7U));
            out[i] = static_cast<char>(static_cast<uint8_t>(buffer[i]) ^ k);
        }
    }

    std::string str() const {
        std::string res;
        res.resize(N > 0 ? N - 1 : 0);
        for (size_t i = 0; i + 1 < N; ++i) {
            uint8_t k = static_cast<uint8_t>(key + (i * 7U));
            res[i] = static_cast<char>(static_cast<uint8_t>(buffer[i]) ^ k);
        }
        return res;
    }
};

template <size_t N>
consteval auto make_obfuscated(const char (&str)[N], uint8_t key = 0x5A) {
    return ObfuscatedString<N>(str, key);
}

template <size_t N>
class DecryptedScope {
private:
    char m_data[N]{};
public:
    explicit DecryptedScope(const ObfuscatedString<N>& obf) noexcept {
        obf.decrypt(m_data);
    }

    ~DecryptedScope() noexcept {
        for (size_t i = 0; i < N; ++i) {
            volatile char* p = &m_data[i];
            *p = 0;
        }
    }

    DecryptedScope(const DecryptedScope&) = delete;
    DecryptedScope& operator=(const DecryptedScope&) = delete;

    [[nodiscard]] const char* c_str() const noexcept {
        return m_data;
    }

    [[nodiscard]] size_t size() const noexcept {
        return N > 0 ? N - 1 : 0;
    }
};

} // namespace maigshield::crypto

#define OBFUSCATE_STACK(varName, str) \
    constexpr uint8_t _obf_key_##varName = static_cast<uint8_t>(((__LINE__ * 37U) ^ (sizeof(str) * 13U) ^ 0x5DU) | 1U); \
    constexpr auto _obf_##varName = ::maigshield::crypto::make_obfuscated(str, _obf_key_##varName); \
    ::maigshield::crypto::DecryptedScope<sizeof(str)> varName(_obf_##varName)

#define OBFUSCATED(str) []() -> std::string { \
    constexpr uint8_t k = static_cast<uint8_t>(((__LINE__ * 37U) ^ (sizeof(str) * 13U) ^ 0x6BU) | 1U); \
    constexpr auto obf = ::maigshield::crypto::make_obfuscated(str, k); \
    return obf.str(); \
}()
