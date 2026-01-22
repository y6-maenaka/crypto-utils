#pragma once

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "key_pair.hpp"
#include "../hash/sha2.hpp"


namespace crypto_utils {
namespace asymmetric {

/**
 * @brief Elliptic curve types
 */
enum class ec_curve {
    secp256k1,  // Bitcoin curve
    secp256r1,  // NIST P-256 (prime256v1)
    secp384r1,  // NIST P-384
    secp521r1   // NIST P-521
};

/**
 * @brief ECDSA (Elliptic Curve Digital Signature Algorithm)
 *
 * Provides digital signatures using elliptic curve cryptography.
 * Smaller keys than RSA with equivalent security.
 */
class ecdsa {
public:
    /**
     * @brief Generate ECDSA key pair
     *
     * @param curve Elliptic curve to use
     * @return result<key_pair> Generated key pair or error
     */
    static core::result<key_pair> generate_key_pair(ec_curve curve) {
        int nid = get_curve_nid(curve);
        if (nid == NID_undef) {
            return core::error(
                core::error_code::invalid_argument,
                "Invalid elliptic curve"
            );
        }

        auto pctx = core::make_pkey_ctx_id(EVP_PKEY_EC, nullptr);
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

        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), nid) <= 0) {
            return core::error(
                core::error_code::key_generation_failed,
                "Failed to set EC curve"
            );
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) {
            return core::error(
                core::error_code::key_generation_failed,
                "Failed to generate ECDSA key pair"
            );
        }

        return key_pair(core::openssl_ptr<EVP_PKEY>(pkey));
    }

    /**
     * @brief Sign data with ECDSA private key
     *
     * Uses SHA-256 hash by default.
     *
     * @tparam Container Type satisfying byte_container concept
     * @param message Data to sign
     * @param key_pair Key pair (uses private key)
     * @param md Message digest algorithm (default: SHA-256)
     * @return result<byte_vector> Signature or error
     */
    template<core::byte_container Container>
    static core::result<core::byte_vector> sign(
        const Container& message,
        const key_pair& key_pair,
        const EVP_MD* md = EVP_sha256()
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

        // Set message digest
        if (EVP_PKEY_CTX_set_signature_md(pctx.get(), md) <= 0) {
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
     * @brief Verify ECDSA signature
     *
     * @tparam Container1 Type satisfying byte_container concept
     * @tparam Container2 Type satisfying byte_container concept
     * @param message Original message
     * @param signature Signature to verify
     * @param key_pair Key pair (uses public key)
     * @param md Message digest algorithm (default: SHA-256)
     * @return result<bool> True if valid, false if invalid, or error
     */
    template<core::byte_container Container1, core::byte_container Container2>
    static core::result<bool> verify(
        const Container1& message,
        const Container2& signature,
        const key_pair& key_pair,
        const EVP_MD* md = EVP_sha256()
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

        // Set message digest
        if (EVP_PKEY_CTX_set_signature_md(pctx.get(), md) <= 0) {
            return core::error(
                core::error_code::verification_failed,
                "Failed to set signature algorithm"
            );
        }

        // Verify
        int result = EVP_PKEY_verify(
            pctx.get(),
            reinterpret_cast<const unsigned char*>(signature.data()),
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

private:
    static int get_curve_nid(ec_curve curve) {
        switch (curve) {
            case ec_curve::secp256k1:
                return NID_secp256k1;
            case ec_curve::secp256r1:
                return NID_X9_62_prime256v1;  // Also known as secp256r1
            case ec_curve::secp384r1:
                return NID_secp384r1;
            case ec_curve::secp521r1:
                return NID_secp521r1;
            default:
                return NID_undef;
        }
    }
};

} // namespace asymmetric
} // namespace crypto_utils
