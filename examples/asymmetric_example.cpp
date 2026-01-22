#include <iostream>
#include <iomanip>
#include <filesystem>
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
    std::cout << "=== Asymmetric Cryptography Examples ===\n\n";

    // RSA Example
    {
        std::cout << "--- RSA (2048-bit) ---\n";

        // Generate key pair
        std::cout << "Generating RSA key pair...\n";
        auto key_result = asymmetric::rsa::generate_key_pair(2048);
        if (!key_result) {
            std::cerr << "Key generation failed\n";
            return 1;
        }
        auto key_pair = std::move(*key_result);
        std::cout << "Key pair generated ✓\n";

        // Save keys
        std::cout << "Saving keys...\n";
        auto save_pub = key_pair.save_public_key("rsa_public.pem");
        auto save_priv = key_pair.save_private_key("rsa_private.pem", "mypassword");

        if (save_pub && save_priv) {
            std::cout << "Keys saved ✓\n";
        }

        // Encryption/Decryption
        std::string message = "Secret RSA message";
        std::cout << "\nMessage: " << message << "\n";

        auto enc_result = asymmetric::rsa::encrypt(message, key_pair);
        if (!enc_result) {
            std::cerr << "Encryption failed\n";
            return 1;
        }
        std::cout << "Encrypted: ";
        print_hex(*enc_result);

        auto dec_result = asymmetric::rsa::decrypt(*enc_result, key_pair);
        if (!dec_result) {
            std::cerr << "Decryption failed\n";
            return 1;
        }
        std::string decrypted(reinterpret_cast<const char*>(dec_result->data()),
                             dec_result->size());
        std::cout << "Decrypted: " << decrypted << "\n";
        std::cout << "Match: " << (decrypted == message ? "✓" : "✗") << "\n";

        // Digital Signature
        std::cout << "\nDigital Signature:\n";
        std::string doc = "Important document";
        std::cout << "Document: " << doc << "\n";

        auto sign_result = asymmetric::rsa::sign(doc, key_pair);
        if (!sign_result) {
            std::cerr << "Signing failed\n";
            return 1;
        }
        std::cout << "Signature: ";
        print_hex(*sign_result);

        auto verify_result = asymmetric::rsa::verify(doc, *sign_result, key_pair);
        if (verify_result && *verify_result) {
            std::cout << "Signature verified ✓\n";
        } else {
            std::cout << "Signature verification failed ✗\n";
        }

        // Test with modified document
        std::string modified_doc = "Important document!";
        auto verify_modified = asymmetric::rsa::verify(modified_doc, *sign_result, key_pair);
        if (verify_modified && !(*verify_modified)) {
            std::cout << "Modified document rejected ✓\n";
        }

        std::cout << "\n";
    }

    // ECDSA Example (New!)
    {
        std::cout << "--- ECDSA (P-256 / secp256r1) ---\n";

        // Generate key pair
        std::cout << "Generating ECDSA key pair...\n";
        auto key_result = asymmetric::ecdsa::generate_key_pair(
            asymmetric::ec_curve::secp256r1
        );
        if (!key_result) {
            std::cerr << "Key generation failed\n";
            return 1;
        }
        auto key_pair = std::move(*key_result);
        std::cout << "Key pair generated ✓\n";

        // Save keys
        auto save_pub = key_pair.save_public_key("ecdsa_public.pem");
        auto save_priv = key_pair.save_private_key("ecdsa_private.pem", "mypassword");

        if (save_pub && save_priv) {
            std::cout << "Keys saved ✓\n";
        }

        // Digital Signature
        std::string message = "ECDSA signed message";
        std::cout << "\nMessage: " << message << "\n";

        auto sign_result = asymmetric::ecdsa::sign(message, key_pair);
        if (!sign_result) {
            std::cerr << "Signing failed\n";
            return 1;
        }
        std::cout << "Signature: ";
        print_hex(*sign_result);

        auto verify_result = asymmetric::ecdsa::verify(message, *sign_result, key_pair);
        if (verify_result && *verify_result) {
            std::cout << "Signature verified ✓\n";
        } else {
            std::cout << "Signature verification failed ✗\n";
        }

        std::cout << "\nNote: ECDSA signatures are smaller than RSA for equivalent security\n";
        std::cout << "P-256 ≈ RSA-3072 in security strength\n";
    }

    // Cleanup
    std::filesystem::remove("rsa_public.pem");
    std::filesystem::remove("rsa_private.pem");
    std::filesystem::remove("ecdsa_public.pem");
    std::filesystem::remove("ecdsa_private.pem");

    return 0;
}
