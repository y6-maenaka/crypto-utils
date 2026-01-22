#pragma once

#include <string>
#include <openssl/err.h>


namespace crypto_utils {
namespace core {

/**
 * @brief Error codes for crypto operations
 */
enum class error_code {
    success = 0,

    // General errors
    invalid_argument,
    out_of_memory,
    internal_error,

    // OpenSSL errors
    openssl_initialization_failed,
    openssl_operation_failed,

    // Cipher errors
    encryption_failed,
    decryption_failed,
    invalid_key_length,
    invalid_iv_length,
    invalid_tag_length,
    invalid_padding,
    authentication_failed,
    random_generation_failed,

    // Hash errors
    hash_failed,
    invalid_digest_algorithm,

    // Asymmetric crypto errors
    key_generation_failed,
    key_load_failed,
    key_save_failed,
    signing_failed,
    verification_failed,

    // Encoding errors
    encoding_failed,
    decoding_failed,

    // File I/O errors
    file_not_found,
    file_read_failed,
    file_write_failed
};

/**
 * @brief Error information class
 *
 * Captures detailed error information including OpenSSL error messages.
 */
class error {
public:
    error() = default;

    /**
     * @brief Construct an error with code and message
     *
     * @param code Error code
     * @param message Error message
     */
    error(error_code code, std::string message = "")
        : code_(code), message_(std::move(message)) {
        if (code != error_code::success) {
            capture_openssl_error();
        }
    }

    /**
     * @brief Get error code
     */
    error_code code() const noexcept { return code_; }

    /**
     * @brief Get error message
     */
    const std::string& message() const noexcept { return message_; }

    /**
     * @brief Get OpenSSL error message
     */
    const std::string& openssl_error() const noexcept { return openssl_error_; }

    /**
     * @brief Check if this is an error
     */
    explicit operator bool() const noexcept {
        return code_ != error_code::success;
    }

private:
    void capture_openssl_error() {
        unsigned long err = ERR_get_error();
        if (err != 0) {
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            openssl_error_ = buf;
        }
    }

    error_code code_ = error_code::success;
    std::string message_;
    std::string openssl_error_;
};

} // namespace core
} // namespace crypto_utils
