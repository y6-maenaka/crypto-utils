#pragma once

#include <memory>
#include <openssl/evp.h>
#include <openssl/bio.h>


namespace crypto_utils {
namespace core {

/**
 * @brief Custom deleters for OpenSSL resources
 *
 * These deleters ensure proper cleanup of OpenSSL objects using RAII.
 */
template<typename T>
struct openssl_deleter;

template<>
struct openssl_deleter<EVP_MD_CTX> {
    void operator()(EVP_MD_CTX* ptr) const noexcept {
        if (ptr) EVP_MD_CTX_free(ptr);
    }
};

template<>
struct openssl_deleter<EVP_CIPHER_CTX> {
    void operator()(EVP_CIPHER_CTX* ptr) const noexcept {
        if (ptr) EVP_CIPHER_CTX_free(ptr);
    }
};

template<>
struct openssl_deleter<EVP_PKEY> {
    void operator()(EVP_PKEY* ptr) const noexcept {
        if (ptr) EVP_PKEY_free(ptr);
    }
};

template<>
struct openssl_deleter<EVP_PKEY_CTX> {
    void operator()(EVP_PKEY_CTX* ptr) const noexcept {
        if (ptr) EVP_PKEY_CTX_free(ptr);
    }
};

template<>
struct openssl_deleter<BIO> {
    void operator()(BIO* ptr) const noexcept {
        if (ptr) BIO_free_all(ptr);
    }
};

/**
 * @brief RAII wrapper for OpenSSL resources
 *
 * Automatically manages the lifetime of OpenSSL objects.
 *
 * @tparam T The OpenSSL type to manage
 */
template<typename T>
using openssl_ptr = std::unique_ptr<T, openssl_deleter<T>>;

/**
 * @brief Factory functions for creating OpenSSL resources
 */

inline openssl_ptr<EVP_MD_CTX> make_md_ctx() {
    return openssl_ptr<EVP_MD_CTX>(EVP_MD_CTX_new());
}

inline openssl_ptr<EVP_CIPHER_CTX> make_cipher_ctx() {
    return openssl_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new());
}

inline openssl_ptr<EVP_PKEY_CTX> make_pkey_ctx(EVP_PKEY* pkey, ENGINE* e = nullptr) {
    return openssl_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(pkey, e));
}

inline openssl_ptr<EVP_PKEY_CTX> make_pkey_ctx_id(int id, ENGINE* e = nullptr) {
    return openssl_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new_id(id, e));
}

inline openssl_ptr<BIO> make_bio_file(const char* filename, const char* mode) {
    return openssl_ptr<BIO>(BIO_new_file(filename, mode));
}

inline openssl_ptr<BIO> make_bio_mem() {
    return openssl_ptr<BIO>(BIO_new(BIO_s_mem()));
}

inline openssl_ptr<BIO> make_bio_s_file() {
    return openssl_ptr<BIO>(BIO_new(BIO_s_file()));
}

inline openssl_ptr<BIO> make_bio_base64() {
    return openssl_ptr<BIO>(BIO_new(BIO_f_base64()));
}

} // namespace core
} // namespace crypto_utils
