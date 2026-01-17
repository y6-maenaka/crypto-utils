#include <iostream>
#include <iomanip>
#include "../crypto_utils.hpp"

using namespace crypto_utils;

void print_hex(const core::byte_vector& data, size_t max = 32) {
    size_t limit = std::min(data.size(), max);
    for (size_t i = 0; i < limit; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    if (data.size() > max) {
        std::cout << "... (" << std::dec << data.size() << " bytes)";
    }
    std::cout << std::dec << "\n";
}

int main() {
    std::cout << "=== Cipher Algorithm Examples ===\n\n";

    std::string plaintext = "This is a secret message that needs encryption!";
    std::cout << "Plaintext: " << plaintext << "\n";
    std::cout << "Length: " << plaintext.size() << " bytes\n\n";

    // AES-256-CBC
    {
        std::cout << "--- AES-256-CBC ---\n";

        // Generate random key
        auto key = cipher::aes_key<cipher::aes_key_size::aes_256>::generate_random();
        std::cout << "Generated 256-bit key\n";

        // Encrypt
        auto enc_result = cipher::aes_256_cbc::encrypt(plaintext, key);
        if (!enc_result) {
            std::cerr << "Encryption failed: " << enc_result.error_value().message() << "\n";
            return 1;
        }
        auto& enc = *enc_result;

        std::cout << "Ciphertext: ";
        print_hex(enc.ciphertext);
        std::cout << "IV: ";
        print_hex(enc.iv);

        // Decrypt
        auto dec_result = cipher::aes_256_cbc::decrypt(enc, key);
        if (!dec_result) {
            std::cerr << "Decryption failed: " << dec_result.error_value().message() << "\n";
            return 1;
        }

        std::string decrypted(reinterpret_cast<const char*>(dec_result->data()),
                             dec_result->size());
        std::cout << "Decrypted: " << decrypted << "\n";
        std::cout << "Match: " << (decrypted == plaintext ? "✓" : "✗") << "\n\n";
    }

    // AES-256-CTR (New!)
    {
        std::cout << "--- AES-256-CTR (Counter Mode) ---\n";

        auto key = cipher::aes_key<cipher::aes_key_size::aes_256>::generate_random();

        auto enc_result = cipher::aes_256_ctr::encrypt(plaintext, key);
        if (!enc_result) {
            std::cerr << "Encryption failed\n";
            return 1;
        }
        auto& enc = *enc_result;

        std::cout << "Ciphertext: ";
        print_hex(enc.ciphertext);
        std::cout << "Nonce: ";
        print_hex(enc.nonce);

        auto dec_result = cipher::aes_256_ctr::decrypt(enc, key);
        if (!dec_result) {
            std::cerr << "Decryption failed\n";
            return 1;
        }

        std::string decrypted(reinterpret_cast<const char*>(dec_result->data()),
                             dec_result->size());
        std::cout << "Decrypted: " << decrypted << "\n";
        std::cout << "Match: " << (decrypted == plaintext ? "✓" : "✗") << "\n\n";
    }

    // AES-256-GCM (New! - Authenticated Encryption)
    {
        std::cout << "--- AES-256-GCM (Authenticated Encryption) ---\n";

        auto key = cipher::aes_key<cipher::aes_key_size::aes_256>::generate_random();

        // Additional Authenticated Data (not encrypted, but authenticated)
        std::string aad = "header-info";
        std::cout << "AAD: " << aad << "\n";

        auto enc_result = cipher::aes_256_gcm::encrypt(
            plaintext, key, std::as_bytes(std::span(aad))
        );
        if (!enc_result) {
            std::cerr << "Encryption failed\n";
            return 1;
        }
        auto& enc = *enc_result;

        std::cout << "Ciphertext: ";
        print_hex(enc.ciphertext);
        std::cout << "IV: ";
        print_hex(enc.iv);
        std::cout << "Auth Tag: ";
        print_hex(enc.tag);

        // Decrypt with authentication
        auto dec_result = cipher::aes_256_gcm::decrypt(
            enc, key, std::as_bytes(std::span(aad))
        );
        if (!dec_result) {
            std::cerr << "Decryption/Authentication failed: "
                      << dec_result.error_value().message() << "\n";
            return 1;
        }

        std::string decrypted(reinterpret_cast<const char*>(dec_result->data()),
                             dec_result->size());
        std::cout << "Decrypted: " << decrypted << "\n";
        std::cout << "Match: " << (decrypted == plaintext ? "✓" : "✗") << "\n";
        std::cout << "Authentication: ✓ (data not tampered)\n\n";

        // Test tampering detection
        std::cout << "Testing tampering detection...\n";
        enc.ciphertext[0] = static_cast<std::byte>(
            static_cast<int>(enc.ciphertext[0]) ^ 0xFF
        );

        auto tampered_result = cipher::aes_256_gcm::decrypt(
            enc, key, std::as_bytes(std::span(aad))
        );
        if (!tampered_result) {
            std::cout << "Tampering detected! ✓\n";
            std::cout << "Error: " << tampered_result.error_value().message() << "\n";
        } else {
            std::cout << "ERROR: Tampering not detected!\n";
        }
    }

    return 0;
}
