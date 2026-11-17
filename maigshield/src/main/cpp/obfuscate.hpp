#pragma once

#include <cstddef>
#include <array>
#include <string>
#include <utility>

namespace maigshield::crypto {

template <size_t N>
struct ObfuscatedString {
    std::array<char, N> buffer{};
    char key{0};

    constexpr explicit ObfuscatedString(const char (&str)[N], char xor_key) noexcept : key(xor_key) {
        for (size_t i = 0; i < N; ++i) {
            buffer[i] = static_cast<char>(str[i] ^ key);
        }
    }

    void decrypt(char* out) const noexcept {
        for (size_t i = 0; i < N; ++i) {
            out[i] = static_cast<char>(buffer[i] ^ key);
        }
    }

    std::string str() const {
        std::string res;
        res.resize(N - 1);
        for (size_t i = 0; i < N - 1; ++i) {
            res[i] = static_cast<char>(buffer[i] ^ key);
        }
        return res;
    }
};

template <size_t N>
consteval auto make_obfuscated(const char (&str)[N], char key = 0x5A) {
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

    [[nodiscard]] const char* c_str() const noexcept {
        return m_data;
    }

    [[nodiscard]] size_t size() const noexcept {
        return N > 0 ? N - 1 : 0;
    }
};

} // namespace maigshield::crypto

#define OBFUSCATE_STACK(varName, str) \
    constexpr auto _obf_##varName = ::maigshield::crypto::make_obfuscated(str, 0x5D); \
    ::maigshield::crypto::DecryptedScope<sizeof(str)> varName(_obf_##varName)

#define OBFUSCATED(str) []() -> std::string { \
    constexpr auto obf = ::maigshield::crypto::make_obfuscated(str, 0x6B); \
    return obf.str(); \
}()
