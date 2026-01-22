#pragma once

#include <openssl/evp.h>
#include "aes_common.hpp"
#include "../core/openssl_ptr.hpp"


namespace crypto_utils {
namespace cipher {

/**
 * @brief AES-CTR mode encryption/decryption
 *
 * Counter mode - operates as a stream cipher.
 * Supports parallel encryption/decryption.
 *
 * @tparam KeySize AES key size (aes_128, aes_192, or aes_256)
 */
template<aes_key_size KeySize>
class aes_ctr {
public:
    static constexpr std::size_t key_size = static_cast<std::size_t>(KeySize);

    /**
     * @brief Encrypted data structure
     *
     * Contains ciphertext and nonce/IV
     */
    struct encrypted_data {
        core::byte_vector ciphertext;
        core::byte_vector nonce;
    };

    /**
     * @brief Encrypt data with AES-CTR
     *
     * Generates a random nonce for each encryption.
     * CTR mode doesn't require padding.
     *
     * @tparam Container Type satisfying byte_container concept
     * @param plaintext Data to encrypt
     * @param key AES key
     * @return result<encrypted_data> Encrypted data or error
     */
    template<core::byte_container Container>
    static core::result<encrypted_data> encrypt(
        const Container& plaintext,
        const aes_key<KeySize>& key
    ) {
        // Generate random nonce
        auto nonce_result = iv_generator::generate_aes_iv();
        if (!nonce_result) {
            return nonce_result.error_value();
        }
        core::byte_vector nonce = std::move(*nonce_result);

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
                key.raw(),
                reinterpret_cast<const unsigned char*>(nonce.data())
            ) != 1) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to initialize AES-CTR encryption"
            );
        }

        // CTR mode doesn't use padding
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

        // Allocate output buffer (same size as plaintext for CTR mode)
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

        return encrypted_data{std::move(ciphertext), std::move(nonce)};
    }

    /**
     * @brief Decrypt data with AES-CTR
     *
     * @param enc_data Encrypted data (ciphertext + nonce)
     * @param key AES key
     * @return result<byte_vector> Decrypted plaintext or error
     */
    static core::result<core::byte_vector> decrypt(
        const encrypted_data& enc_data,
        const aes_key<KeySize>& key
    ) {
        if (enc_data.nonce.size() != aes_iv_size) {
            return core::error(
                core::error_code::invalid_iv_length,
                "Invalid nonce length for AES-CTR"
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
                key.raw(),
                reinterpret_cast<const unsigned char*>(enc_data.nonce.data())
            ) != 1) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to initialize AES-CTR decryption"
            );
        }

        // CTR mode doesn't use padding
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

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

        int final_len = 0;
        if (EVP_DecryptFinal_ex(
                ctx.get(),
                reinterpret_cast<unsigned char*>(plaintext.data()) + outlen,
                &final_len
            ) != 1) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to finalize decryption"
            );
        }

        plaintext.resize(outlen + final_len);

        return plaintext;
    }

private:
    static const EVP_CIPHER* get_cipher() {
        if constexpr (KeySize == aes_key_size::aes_128) {
            return EVP_aes_128_ctr();
        } else if constexpr (KeySize == aes_key_size::aes_192) {
            return EVP_aes_192_ctr();
        } else if constexpr (KeySize == aes_key_size::aes_256) {
            return EVP_aes_256_ctr();
        }
    }
};

// Convenient type aliases
using aes_128_ctr = aes_ctr<aes_key_size::aes_128>;
using aes_192_ctr = aes_ctr<aes_key_size::aes_192>;
using aes_256_ctr = aes_ctr<aes_key_size::aes_256>;

} // namespace cipher
} // namespace crypto_utils
