#pragma once

#include <array>
#include <cstddef>
#include <stdexcept>
#include <algorithm>
#include <openssl/rand.h>
#include "../core/result.hpp"
#include "../core/error.hpp"
#include "../core/concepts.hpp"


namespace crypto_utils {
namespace cipher {

/**
 * @brief AES key sizes
 */
enum class aes_key_size : std::size_t {
    aes_128 = 16,
    aes_192 = 24,
    aes_256 = 32
};

/**
 * @brief AES constants
 */
constexpr std::size_t aes_block_size = 16;
constexpr std::size_t aes_iv_size = 16;

/**
 * @brief AES key class
 *
 * Type-safe wrapper for AES keys with compile-time size checking.
 *
 * @tparam KeySize Key size (aes_128, aes_192, or aes_256)
 */
template<aes_key_size KeySize>
class aes_key {
public:
    static constexpr std::size_t key_size = static_cast<std::size_t>(KeySize);

    /**
     * @brief Construct key from byte container
     *
     * @tparam Container Type satisfying byte_container concept
     * @param key_data Key bytes (must be exactly key_size bytes)
     * @throws std::invalid_argument if size doesn't match
     */
    template<core::byte_container Container>
    explicit aes_key(const Container& key_data) {
        if (key_data.size() != key_size) {
            throw std::invalid_argument(
                "Invalid AES key size: expected " +
                std::to_string(key_size) +
                ", got " + std::to_string(key_data.size())
            );
        }
        std::copy_n(
            static_cast<const std::byte*>(key_data.data()),
            key_size,
            key_.begin()
        );
    }

    /**
     * @brief Generate random AES key
     *
     * @return Random AES key
     * @throws std::runtime_error if random generation fails
     */
    static aes_key generate_random() {
        aes_key key;
        if (RAND_bytes(
                reinterpret_cast<unsigned char*>(key.key_.data()),
                key_size
            ) != 1) {
            throw std::runtime_error("Failed to generate random AES key");
        }
        return key;
    }

    /**
     * @brief Get raw key data
     */
    const std::byte* data() const noexcept { return key_.data(); }

    /**
     * @brief Get key size
     */
    constexpr std::size_t size() const noexcept { return key_size; }

    /**
     * @brief Get raw key data (for OpenSSL)
     */
    const unsigned char* raw() const noexcept {
        return reinterpret_cast<const unsigned char*>(key_.data());
    }

private:
    aes_key() = default;
    std::array<std::byte, key_size> key_;
};

/**
 * @brief IV (Initialization Vector) generator
 */
class iv_generator {
public:
    /**
     * @brief Generate random IV
     *
     * @param size IV size in bytes
     * @return result<byte_vector> Random IV or error
     */
    static core::result<core::byte_vector> generate(std::size_t size) {
        core::byte_vector iv(size);
        if (RAND_bytes(
                reinterpret_cast<unsigned char*>(iv.data()),
                size
            ) != 1) {
            return core::error(
                core::error_code::internal_error,
                "Failed to generate random IV"
            );
        }
        return iv;
    }

    /**
     * @brief Generate random IV for AES
     *
     * @return result<byte_vector> Random 16-byte IV or error
     */
    static core::result<core::byte_vector> generate_aes_iv() {
        return generate(aes_iv_size);
    }
};

} // namespace cipher
} // namespace crypto_utils
