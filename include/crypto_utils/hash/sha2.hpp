#pragma once

#include <openssl/evp.h>
#include "hash_algorithm.hpp"
#include "../core/openssl_ptr.hpp"
#include "../core/error.hpp"


namespace crypto_utils {
namespace hash {

/**
 * @brief SHA-2 family hash algorithm
 *
 * Supports SHA-224, SHA-256, SHA-384, and SHA-512.
 *
 * @tparam DigestBits Hash output size in bits (224, 256, 384, or 512)
 */
template<std::size_t DigestBits>
class sha2 : public hash_algorithm<sha2<DigestBits>> {
    static_assert(
        DigestBits == 224 || DigestBits == 256 ||
        DigestBits == 384 || DigestBits == 512,
        "SHA-2 digest size must be 224, 256, 384, or 512 bits"
    );

public:
    static constexpr std::size_t digest_size = DigestBits / 8;

    /**
     * @brief Implementation of hash algorithm
     */
    static core::result<core::byte_vector> hash_impl(
        const std::byte* data,
        std::size_t size
    ) {
        auto ctx = core::make_md_ctx();
        if (!ctx) {
            return core::error(
                core::error_code::openssl_initialization_failed,
                "Failed to create MD context"
            );
        }

        const EVP_MD* md = get_digest_algorithm();
        if (!md) {
            return core::error(
                core::error_code::invalid_digest_algorithm,
                "Invalid SHA-2 digest size"
            );
        }

        if (EVP_DigestInit_ex(ctx.get(), md, nullptr) <= 0) {
            return core::error(
                core::error_code::hash_failed,
                "Failed to initialize digest"
            );
        }

        if (EVP_DigestUpdate(ctx.get(), data, size) <= 0) {
            return core::error(
                core::error_code::hash_failed,
                "Failed to update digest"
            );
        }

        core::byte_vector result(digest_size);
        unsigned int out_len = 0;

        if (EVP_DigestFinal_ex(
                ctx.get(),
                reinterpret_cast<unsigned char*>(result.data()),
                &out_len
            ) <= 0 || out_len != digest_size) {
            return core::error(
                core::error_code::hash_failed,
                "Failed to finalize digest"
            );
        }

        return result;
    }

    /**
     * @brief Streaming hash context for SHA-2
     */
    class streaming_context : public hash_algorithm<sha2<DigestBits>>::context {
    public:
        streaming_context() : ctx_(core::make_md_ctx()) {
            if (!ctx_) {
                throw std::runtime_error("Failed to create MD context");
            }
            const EVP_MD* md = get_digest_algorithm();
            if (EVP_DigestInit_ex(ctx_.get(), md, nullptr) <= 0) {
                throw std::runtime_error("Failed to initialize digest");
            }
        }

        core::result<void> update(std::span<const std::byte> data) override {
            if (EVP_DigestUpdate(ctx_.get(), data.data(), data.size()) <= 0) {
                return core::error(
                    core::error_code::hash_failed,
                    "Failed to update digest"
                );
            }
            return {};
        }

        core::result<core::byte_vector> finalize() override {
            core::byte_vector result(digest_size);
            unsigned int out_len = 0;

            if (EVP_DigestFinal_ex(
                    ctx_.get(),
                    reinterpret_cast<unsigned char*>(result.data()),
                    &out_len
                ) <= 0) {
                return core::error(
                    core::error_code::hash_failed,
                    "Failed to finalize digest"
                );
            }

            return result;
        }

    private:
        core::openssl_ptr<EVP_MD_CTX> ctx_;
    };

private:
    static const EVP_MD* get_digest_algorithm() {
        if constexpr (DigestBits == 224) {
            return EVP_sha224();
        } else if constexpr (DigestBits == 256) {
            return EVP_sha256();
        } else if constexpr (DigestBits == 384) {
            return EVP_sha384();
        } else if constexpr (DigestBits == 512) {
            return EVP_sha512();
        }
        return nullptr;
    }
};

// Convenient type aliases
using sha224 = sha2<224>;
using sha256 = sha2<256>;
using sha384 = sha2<384>;
using sha512 = sha2<512>;

} // namespace hash
} // namespace crypto_utils
