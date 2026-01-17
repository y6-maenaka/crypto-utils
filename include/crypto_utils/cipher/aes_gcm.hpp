#pragma once

#include <openssl/evp.h>
#include "aes_common.hpp"
#include "../core/openssl_ptr.hpp"


namespace crypto_utils {
namespace cipher {

/**
 * @brief AES-GCM mode encryption/decryption
 *
 * Galois/Counter Mode - Authenticated Encryption with Associated Data (AEAD).
 * Provides both confidentiality and authenticity.
 *
 * @tparam KeySize AES key size (aes_128, aes_192, or aes_256)
 */
template<aes_key_size KeySize>
class aes_gcm {
public:
    static constexpr std::size_t key_size = static_cast<std::size_t>(KeySize);
    static constexpr std::size_t gcm_iv_size = 12;   // 96 bits (recommended for GCM)
    static constexpr std::size_t gcm_tag_size = 16;  // 128 bits

    /**
     * @brief Encrypted data structure
     *
     * Contains ciphertext, IV, and authentication tag
     */
    struct encrypted_data {
        core::byte_vector ciphertext;
        core::byte_vector iv;
        core::byte_vector tag;
    };

    /**
     * @brief Encrypt data with AES-GCM
     *
     * Generates a random IV for each encryption.
     * Produces authentication tag for integrity verification.
     *
     * @tparam Container Type satisfying byte_container concept
     * @param plaintext Data to encrypt
     * @param key AES key
     * @param aad Additional Authenticated Data (optional, not encrypted but authenticated)
     * @return result<encrypted_data> Encrypted data with tag or error
     */
    template<core::byte_container Container>
    static core::result<encrypted_data> encrypt(
        const Container& plaintext,
        const aes_key<KeySize>& key,
        std::span<const std::byte> aad = {}
    ) {
        // Generate random IV (12 bytes for GCM)
        core::byte_vector iv(gcm_iv_size);
        if (RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), gcm_iv_size) != 1) {
            return core::error(
                core::error_code::random_generation_failed,
                "Failed to generate random IV"
            );
        }

        // Create cipher context
        auto ctx = core::make_cipher_ctx();
        if (!ctx) {
            return core::error(
                core::error_code::openssl_initialization_failed,
                "Failed to create cipher context"
            );
        }

        const EVP_CIPHER* cipher = get_cipher();

        // Initialize encryption
        if (EVP_EncryptInit_ex(
                ctx.get(),
                cipher,
                nullptr,
                nullptr,
                nullptr
            ) != 1) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to initialize AES-GCM encryption"
            );
        }

        // Set IV length (must be done before setting IV)
        if (EVP_CIPHER_CTX_ctrl(
                ctx.get(),
                EVP_CTRL_GCM_SET_IVLEN,
                gcm_iv_size,
                nullptr
            ) != 1) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to set IV length"
            );
        }

        // Set key and IV
        if (EVP_EncryptInit_ex(
                ctx.get(),
                nullptr,
                nullptr,
                key.raw(),
                reinterpret_cast<const unsigned char*>(iv.data())
            ) != 1) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to set key and IV"
            );
        }

        // Process AAD if provided
        if (!aad.empty()) {
            int outlen = 0;
            if (EVP_EncryptUpdate(
                    ctx.get(),
                    nullptr,
                    &outlen,
                    reinterpret_cast<const unsigned char*>(aad.data()),
                    aad.size()
                ) != 1) {
                return core::error(
                    core::error_code::encryption_failed,
                    "Failed to process AAD"
                );
            }
        }

        // Allocate output buffer
        core::byte_vector ciphertext(plaintext.size());
        int outlen = 0;

        // Encrypt
        if (EVP_EncryptUpdate(
                ctx.get(),
                reinterpret_cast<unsigned char*>(ciphertext.data()),
                &outlen,
                reinterpret_cast<const unsigned char*>(plaintext.data()),
                plaintext.size()
            ) != 1) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to encrypt data"
            );
        }

        int final_len = 0;
        if (EVP_EncryptFinal_ex(
                ctx.get(),
                reinterpret_cast<unsigned char*>(ciphertext.data()) + outlen,
                &final_len
            ) != 1) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to finalize encryption"
            );
        }

        ciphertext.resize(outlen + final_len);

        // Get authentication tag
        core::byte_vector tag(gcm_tag_size);
        if (EVP_CIPHER_CTX_ctrl(
                ctx.get(),
                EVP_CTRL_GCM_GET_TAG,
                gcm_tag_size,
                tag.data()
            ) != 1) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to get authentication tag"
            );
        }

        return encrypted_data{std::move(ciphertext), std::move(iv), std::move(tag)};
    }

    /**
     * @brief Decrypt and authenticate data with AES-GCM
     *
     * Verifies authentication tag before returning plaintext.
     * If authentication fails, data has been tampered with.
     *
     * @param enc_data Encrypted data (ciphertext + IV + tag)
     * @param key AES key
     * @param aad Additional Authenticated Data (must match encryption)
     * @return result<byte_vector> Decrypted plaintext or error (authentication failure)
     */
    static core::result<core::byte_vector> decrypt(
        const encrypted_data& enc_data,
        const aes_key<KeySize>& key,
        std::span<const std::byte> aad = {}
    ) {
        if (enc_data.iv.size() != gcm_iv_size) {
            return core::error(
                core::error_code::invalid_iv_length,
                "Invalid IV length for AES-GCM"
            );
        }

        if (enc_data.tag.size() != gcm_tag_size) {
            return core::error(
                core::error_code::invalid_tag_length,
                "Invalid tag length for AES-GCM"
            );
        }

        auto ctx = core::make_cipher_ctx();
        if (!ctx) {
            return core::error(
                core::error_code::openssl_initialization_failed,
                "Failed to create cipher context"
            );
        }

        const EVP_CIPHER* cipher = get_cipher();

        // Initialize decryption
        if (EVP_DecryptInit_ex(
                ctx.get(),
                cipher,
                nullptr,
                nullptr,
                nullptr
            ) != 1) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to initialize AES-GCM decryption"
            );
        }

        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(
                ctx.get(),
                EVP_CTRL_GCM_SET_IVLEN,
                gcm_iv_size,
                nullptr
            ) != 1) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to set IV length"
            );
        }

        // Set key and IV
        if (EVP_DecryptInit_ex(
                ctx.get(),
                nullptr,
                nullptr,
                key.raw(),
                reinterpret_cast<const unsigned char*>(enc_data.iv.data())
            ) != 1) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to set key and IV"
            );
        }

        // Process AAD if provided
        if (!aad.empty()) {
            int outlen = 0;
            if (EVP_DecryptUpdate(
                    ctx.get(),
                    nullptr,
                    &outlen,
                    reinterpret_cast<const unsigned char*>(aad.data()),
                    aad.size()
                ) != 1) {
                return core::error(
                    core::error_code::decryption_failed,
                    "Failed to process AAD"
                );
            }
        }

        // Allocate output buffer
        core::byte_vector plaintext(enc_data.ciphertext.size());
        int outlen = 0;

        // Decrypt
        if (EVP_DecryptUpdate(
                ctx.get(),
                reinterpret_cast<unsigned char*>(plaintext.data()),
                &outlen,
                reinterpret_cast<const unsigned char*>(enc_data.ciphertext.data()),
                enc_data.ciphertext.size()
            ) != 1) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to decrypt data"
            );
        }

        // Set expected tag value
        if (EVP_CIPHER_CTX_ctrl(
                ctx.get(),
                EVP_CTRL_GCM_SET_TAG,
                gcm_tag_size,
                const_cast<std::byte*>(enc_data.tag.data())
            ) != 1) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to set authentication tag"
            );
        }

        // Finalize and verify tag
        int final_len = 0;
        if (EVP_DecryptFinal_ex(
                ctx.get(),
                reinterpret_cast<unsigned char*>(plaintext.data()) + outlen,
                &final_len
            ) <= 0) {
            return core::error(
                core::error_code::authentication_failed,
                "Authentication failed - data may have been tampered with"
            );
        }

        plaintext.resize(outlen + final_len);

        return plaintext;
    }

private:
    static const EVP_CIPHER* get_cipher() {
        if constexpr (KeySize == aes_key_size::aes_128) {
            return EVP_aes_128_gcm();
        } else if constexpr (KeySize == aes_key_size::aes_192) {
            return EVP_aes_192_gcm();
        } else if constexpr (KeySize == aes_key_size::aes_256) {
            return EVP_aes_256_gcm();
        }
    }
};

// Convenient type aliases
using aes_128_gcm = aes_gcm<aes_key_size::aes_128>;
using aes_192_gcm = aes_gcm<aes_key_size::aes_192>;
using aes_256_gcm = aes_gcm<aes_key_size::aes_256>;

} // namespace cipher
} // namespace crypto_utils
