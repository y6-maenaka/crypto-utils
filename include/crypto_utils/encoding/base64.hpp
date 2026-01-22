#pragma once

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "../core/result.hpp"
#include "../core/openssl_ptr.hpp"
#include "../core/concepts.hpp"


namespace crypto_utils {
namespace encoding {

/**
 * @brief Base64 encoding and decoding
 *
 * RFC 4648 compliant Base64 encoding.
 */
class base64 {
public:
    /**
     * @brief Encode data to Base64
     *
     * @tparam Container Type satisfying byte_container concept
     * @param input Data to encode
     * @return result<byte_vector> Base64-encoded data or error
     */
    template<core::byte_container Container>
    static core::result<core::byte_vector> encode(const Container& input) {
        auto b64 = core::make_bio_base64();
        if (!b64) {
            return core::error(
                core::error_code::encoding_failed,
                "Failed to create Base64 BIO"
            );
        }

        auto bio = core::make_bio_mem();
        if (!bio) {
            return core::error(
                core::error_code::encoding_failed,
                "Failed to create memory BIO"
            );
        }

        // No newlines in output
        BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

        // Chain BIOs: b64 -> bio (memory)
        BIO* chain = BIO_push(b64.get(), bio.get());

        // Write data
        int written = BIO_write(
            chain,
            input.data(),
            input.size()
        );

        if (written <= 0) {
            return core::error(
                core::error_code::encoding_failed,
                "Failed to write data to BIO"
            );
        }

        // Flush
        if (BIO_flush(chain) != 1) {
            return core::error(
                core::error_code::encoding_failed,
                "Failed to flush BIO"
            );
        }

        // Get encoded data
        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio.get(), &bufferPtr);

        core::byte_vector result(bufferPtr->length);
        std::copy_n(
            reinterpret_cast<const std::byte*>(bufferPtr->data),
            bufferPtr->length,
            result.begin()
        );

        return result;
    }

    /**
     * @brief Decode Base64 data
     *
     * @tparam Container Type satisfying byte_container concept
     * @param input Base64-encoded data
     * @return result<byte_vector> Decoded data or error
     */
    template<core::byte_container Container>
    static core::result<core::byte_vector> decode(const Container& input) {
        auto b64 = core::make_bio_base64();
        if (!b64) {
            return core::error(
                core::error_code::decoding_failed,
                "Failed to create Base64 BIO"
            );
        }

        auto bio = core::make_bio_mem();
        if (!bio) {
            return core::error(
                core::error_code::decoding_failed,
                "Failed to create memory BIO"
            );
        }

        // Write input to memory BIO
        if (BIO_write(bio.get(), input.data(), input.size()) <= 0) {
            return core::error(
                core::error_code::decoding_failed,
                "Failed to write data to BIO"
            );
        }

        // No newlines expected
        BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

        // Chain BIOs: b64 -> bio
        BIO* chain = BIO_push(b64.get(), bio.get());

        // Calculate max decoded size (Base64: 4 bytes -> 3 bytes)
        const std::size_t max_len = (input.size() / 4) * 3 + 3;

        core::byte_vector result(max_len);

        // Read decoded data
        int decoded_len = BIO_read(
            chain,
            result.data(),
            max_len
        );

        if (decoded_len < 0) {
            return core::error(
                core::error_code::decoding_failed,
                "Failed to decode Base64 data"
            );
        }

        result.resize(decoded_len);
        return result;
    }
};

} // namespace encoding
} // namespace crypto_utils
