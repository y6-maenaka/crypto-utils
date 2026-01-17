#pragma once

#include <filesystem>
#include <string_view>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "../core/result.hpp"
#include "../core/openssl_ptr.hpp"


namespace crypto_utils {
namespace asymmetric {

/**
 * @brief Unified key pair management for asymmetric cryptography
 *
 * Manages EVP_PKEY for RSA, ECDSA, and other asymmetric algorithms.
 */
class key_pair {
public:
    key_pair() = default;

    /**
     * @brief Construct from OpenSSL EVP_PKEY
     */
    explicit key_pair(core::openssl_ptr<EVP_PKEY> pkey)
        : pkey_(std::move(pkey)) {}

    /**
     * @brief Save public key to PEM file
     *
     * @param path File path
     * @return result<void> Success or error
     */
    core::result<void> save_public_key(const std::filesystem::path& path) const {
        auto bio = core::make_bio_file(path.c_str(), "w");
        if (!bio) {
            return core::error(
                core::error_code::file_write_failed,
                "Failed to open file for writing: " + path.string()
            );
        }

        if (PEM_write_bio_PUBKEY(bio.get(), pkey_.get()) != 1) {
            return core::error(
                core::error_code::key_save_failed,
                "Failed to write public key"
            );
        }

        return {};
    }

    /**
     * @brief Save private key to PEM file (optionally encrypted)
     *
     * @param path File path
     * @param passphrase Optional passphrase (uses AES-256-CBC if provided)
     * @return result<void> Success or error
     */
    core::result<void> save_private_key(
        const std::filesystem::path& path,
        std::string_view passphrase = ""
    ) const {
        auto bio = core::make_bio_file(path.c_str(), "w");
        if (!bio) {
            return core::error(
                core::error_code::file_write_failed,
                "Failed to open file for writing: " + path.string()
            );
        }

        const EVP_CIPHER* cipher = passphrase.empty() ? nullptr : EVP_aes_256_cbc();
        const char* pass_ptr = passphrase.empty()
            ? nullptr
            : passphrase.data();
        const int pass_len = passphrase.empty() ? 0 : passphrase.size();

        if (PEM_write_bio_PKCS8PrivateKey(
                bio.get(),
                pkey_.get(),
                cipher,
                pass_ptr,
                pass_len,
                nullptr,
                nullptr
            ) != 1) {
            return core::error(
                core::error_code::key_save_failed,
                "Failed to write private key"
            );
        }

        return {};
    }

    /**
     * @brief Load public key from PEM file
     *
     * @param path File path
     * @return result<key_pair> Loaded key pair or error
     */
    static core::result<key_pair> load_public_key(const std::filesystem::path& path) {
        auto bio = core::make_bio_file(path.c_str(), "r");
        if (!bio) {
            return core::error(
                core::error_code::file_not_found,
                "Failed to open file: " + path.string()
            );
        }

        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
        if (!pkey) {
            return core::error(
                core::error_code::key_load_failed,
                "Failed to read public key"
            );
        }

        return key_pair(core::openssl_ptr<EVP_PKEY>(pkey));
    }

    /**
     * @brief Load private key from PEM file
     *
     * @param path File path
     * @param passphrase Optional passphrase for encrypted keys
     * @return result<key_pair> Loaded key pair or error
     */
    static core::result<key_pair> load_private_key(
        const std::filesystem::path& path,
        std::string_view passphrase = ""
    ) {
        auto bio = core::make_bio_file(path.c_str(), "r");
        if (!bio) {
            return core::error(
                core::error_code::file_not_found,
                "Failed to open file: " + path.string()
            );
        }

        const char* pass_ptr = passphrase.empty() ? nullptr : passphrase.data();

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(
            bio.get(),
            nullptr,
            nullptr,
            const_cast<char*>(pass_ptr)
        );

        if (!pkey) {
            return core::error(
                core::error_code::key_load_failed,
                "Failed to read private key (wrong passphrase?)"
            );
        }

        return key_pair(core::openssl_ptr<EVP_PKEY>(pkey));
    }

    /**
     * @brief Get raw EVP_PKEY pointer
     */
    EVP_PKEY* get() const noexcept { return pkey_.get(); }

    /**
     * @brief Check if key pair is valid
     */
    bool is_valid() const noexcept { return pkey_ != nullptr; }

    /**
     * @brief Boolean conversion for validity check
     */
    explicit operator bool() const noexcept { return is_valid(); }

private:
    core::openssl_ptr<EVP_PKEY> pkey_;
};

} // namespace asymmetric
} // namespace crypto_utils
