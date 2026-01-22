#pragma once

#include <openssl/evp.h>
#include "hash_algorithm.hpp"
#include "../core/openssl_ptr.hpp"
#include "../core/error.hpp"


namespace crypto_utils {
namespace hash {

/**
 * @brief SHA-1 hash algorithm
 *
 * @warning SHA-1 is cryptographically broken and should not be used
 *          for security-critical applications. Use SHA-2 or SHA-3 instead.
 */
class sha1 : public hash_algorithm<sha1> {
public:
    static constexpr std::size_t digest_size = 20;

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

        const EVP_MD* md = EVP_sha1();
        if (!md) {
            return core::error(
                core::error_code::invalid_digest_algorithm,
                "Failed to get SHA-1 algorithm"
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
     * @brief Streaming hash context for SHA-1
     */
    class streaming_context : public hash_algorithm<sha1>::context {
    public:
        streaming_context() : ctx_(core::make_md_ctx()) {
            if (!ctx_) {
                throw std::runtime_error("Failed to create MD context");
            }
            const EVP_MD* md = EVP_sha1();
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
};

} // namespace hash
} // namespace crypto_utils
