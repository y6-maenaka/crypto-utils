#pragma once

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "key_pair.hpp"
#include "../hash/sha2.hpp"


namespace crypto_utils {
namespace asymmetric {

/**
 * @brief RSA encryption and digital signatures
 */
class rsa {
public:
    /**
     * @brief Generate RSA key pair
     *
     * @param key_bits Key size in bits (recommended: 2048 or 4096)
     * @return result<key_pair> Generated key pair or error
     */
    static core::result<key_pair> generate_key_pair(int key_bits) {
        auto pctx = core::make_pkey_ctx_id(EVP_PKEY_RSA, nullptr);
        if (!pctx) {
            return core::error(
                core::error_code::key_generation_failed,
                "Failed to create PKEY context"
            );
        }

        if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
            return core::error(
                core::error_code::key_generation_failed,
                "Failed to initialize key generation"
            );
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx.get(), key_bits) <= 0) {
            return core::error(
                core::error_code::key_generation_failed,
                "Failed to set RSA key bits"
            );
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) {
            return core::error(
                core::error_code::key_generation_failed,
                "Failed to generate RSA key pair"
            );
        }

        return key_pair(core::openssl_ptr<EVP_PKEY>(pkey));
    }

    /**
     * @brief Encrypt data with RSA public key
     *
     * Uses OAEP padding (secure padding scheme).
     *
     * @tparam Container Type satisfying byte_container concept
     * @param plaintext Data to encrypt
     * @param key_pair Key pair (uses public key)
     * @return result<byte_vector> Encrypted data or error
     */
    template<core::byte_container Container>
    static core::result<core::byte_vector> encrypt(
        const Container& plaintext,
        const key_pair& key_pair
    ) {
        auto pctx = core::make_pkey_ctx(key_pair.get(), nullptr);
        if (!pctx) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to create PKEY context"
            );
        }

        if (EVP_PKEY_encrypt_init(pctx.get()) <= 0) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to initialize encryption"
            );
        }

        // Set OAEP padding (secure)
        if (EVP_PKEY_CTX_set_rsa_padding(pctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to set RSA padding"
            );
        }

        // Get output size
        std::size_t outlen = 0;
        if (EVP_PKEY_encrypt(
                pctx.get(),
                nullptr,
                &outlen,
                static_cast<const unsigned char*>(plaintext.data()),
                plaintext.size()
            ) <= 0) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to determine output size"
            );
        }

        // Encrypt
        core::byte_vector ciphertext(outlen);
        if (EVP_PKEY_encrypt(
                pctx.get(),
                reinterpret_cast<unsigned char*>(ciphertext.data()),
                &outlen,
                static_cast<const unsigned char*>(plaintext.data()),
                plaintext.size()
            ) <= 0) {
            return core::error(
                core::error_code::encryption_failed,
                "Failed to encrypt data"
            );
        }

        ciphertext.resize(outlen);
        return ciphertext;
    }

    /**
     * @brief Decrypt data with RSA private key
     *
     * @tparam Container Type satisfying byte_container concept
     * @param ciphertext Encrypted data
     * @param key_pair Key pair (uses private key)
     * @return result<byte_vector> Decrypted data or error
     */
    template<core::byte_container Container>
    static core::result<core::byte_vector> decrypt(
        const Container& ciphertext,
        const key_pair& key_pair
    ) {
        auto pctx = core::make_pkey_ctx(key_pair.get(), nullptr);
        if (!pctx) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to create PKEY context"
            );
        }

        if (EVP_PKEY_decrypt_init(pctx.get()) <= 0) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to initialize decryption"
            );
        }

        // Set OAEP padding
        if (EVP_PKEY_CTX_set_rsa_padding(pctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to set RSA padding"
            );
        }

        // Get output size
        std::size_t outlen = 0;
        if (EVP_PKEY_decrypt(
                pctx.get(),
                nullptr,
                &outlen,
                static_cast<const unsigned char*>(ciphertext.data()),
                ciphertext.size()
            ) <= 0) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to determine output size"
            );
        }

        // Decrypt
        core::byte_vector plaintext(outlen);
        if (EVP_PKEY_decrypt(
                pctx.get(),
                reinterpret_cast<unsigned char*>(plaintext.data()),
                &outlen,
                static_cast<const unsigned char*>(ciphertext.data()),
                ciphertext.size()
            ) <= 0) {
            return core::error(
                core::error_code::decryption_failed,
                "Failed to decrypt data"
            );
        }

        plaintext.resize(outlen);
        return plaintext;
    }

    /**
     * @brief Sign data with RSA private key
     *
     * Uses SHA-256 hash and PKCS#1 v1.5 padding.
     *
     * @tparam Container Type satisfying byte_container concept
     * @param message Data to sign
     * @param key_pair Key pair (uses private key)
     * @return result<byte_vector> Signature or error
     */
    template<core::byte_container Container>
    static core::result<core::byte_vector> sign(
        const Container& message,
        const key_pair& key_pair
    ) {
        // Hash the message with SHA-256
        auto hash_result = hash::sha256::hash(message);
        if (!hash_result) {
            return hash_result.error_value();
        }
        auto digest = *hash_result;

        auto pctx = core::make_pkey_ctx(key_pair.get(), nullptr);
        if (!pctx) {
            return core::error(
                core::error_code::signing_failed,
                "Failed to create PKEY context"
            );
        }

        if (EVP_PKEY_sign_init(pctx.get()) <= 0) {
            return core::error(
                core::error_code::signing_failed,
                "Failed to initialize signing"
            );
        }

        // Set SHA-256 as message digest
        if (EVP_PKEY_CTX_set_signature_md(pctx.get(), EVP_sha256()) <= 0) {
            return core::error(
                core::error_code::signing_failed,
                "Failed to set signature algorithm"
            );
        }

        // Get signature size
        std::size_t siglen = 0;
        if (EVP_PKEY_sign(
                pctx.get(),
                nullptr,
                &siglen,
                reinterpret_cast<const unsigned char*>(digest.data()),
                digest.size()
            ) <= 0) {
            return core::error(
                core::error_code::signing_failed,
                "Failed to determine signature size"
            );
        }

        // Sign
        core::byte_vector signature(siglen);
        if (EVP_PKEY_sign(
                pctx.get(),
                reinterpret_cast<unsigned char*>(signature.data()),
                &siglen,
                reinterpret_cast<const unsigned char*>(digest.data()),
                digest.size()
            ) <= 0) {
            return core::error(
                core::error_code::signing_failed,
                "Failed to generate signature"
            );
        }

        signature.resize(siglen);
        return signature;
    }

    /**
     * @brief Verify RSA signature
     *
     * @tparam Container1 Type satisfying byte_container concept
     * @tparam Container2 Type satisfying byte_container concept
     * @param message Original message
     * @param signature Signature to verify
     * @param key_pair Key pair (uses public key)
     * @return result<bool> True if valid, false if invalid, or error
     */
    template<core::byte_container Container1, core::byte_container Container2>
    static core::result<bool> verify(
        const Container1& message,
        const Container2& signature,
        const key_pair& key_pair
    ) {
        // Hash the message
        auto hash_result = hash::sha256::hash(message);
        if (!hash_result) {
            return hash_result.error_value();
        }
        auto digest = *hash_result;

        auto pctx = core::make_pkey_ctx(key_pair.get(), nullptr);
        if (!pctx) {
            return core::error(
                core::error_code::verification_failed,
                "Failed to create PKEY context"
            );
        }

        if (EVP_PKEY_verify_init(pctx.get()) <= 0) {
            return core::error(
                core::error_code::verification_failed,
                "Failed to initialize verification"
            );
        }

        // Set SHA-256
        if (EVP_PKEY_CTX_set_signature_md(pctx.get(), EVP_sha256()) <= 0) {
            return core::error(
                core::error_code::verification_failed,
                "Failed to set signature algorithm"
            );
        }

        // Verify
        int result = EVP_PKEY_verify(
            pctx.get(),
            static_cast<const unsigned char*>(signature.data()),
            signature.size(),
            reinterpret_cast<const unsigned char*>(digest.data()),
            digest.size()
        );

        if (result < 0) {
            return core::error(
                core::error_code::verification_failed,
                "Verification error"
            );
        }

        return result == 1;
    }
};

} // namespace asymmetric
} // namespace crypto_utils
