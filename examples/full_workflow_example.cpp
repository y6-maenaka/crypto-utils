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
    std::cout << "=== Full Cryptographic Workflow Example ===\n\n";
    std::cout << "Scenario: Secure message transmission with integrity verification\n\n";

    // Step 1: Prepare message
    std::string message = "This is a highly confidential message that must be "
                         "encrypted and authenticated!";
    std::cout << "1. Original Message:\n   " << message << "\n\n";

    // Step 2: Hash the message (for integrity check)
    std::cout << "2. Computing SHA-256 hash...\n";
    auto hash_result = hash::sha256::hash(message);
    if (!hash_result) {
        std::cerr << "Hashing failed\n";
        return 1;
    }
    std::cout << "   Hash: ";
    print_hex(*hash_result);
    std::cout << "\n";

    // Step 3: Encrypt with AES-256-GCM (Authenticated Encryption)
    std::cout << "3. Encrypting with AES-256-GCM...\n";
    auto aes_key = cipher::aes_key<cipher::aes_key_size::aes_256>::generate_random();

    std::string aad = "message-header-v1";
    auto enc_result = cipher::aes_256_gcm::encrypt(
        message, aes_key, std::as_bytes(std::span(aad))
    );
    if (!enc_result) {
        std::cerr << "Encryption failed\n";
        return 1;
    }
    auto& encrypted = *enc_result;

    std::cout << "   Ciphertext: ";
    print_hex(encrypted.ciphertext);
    std::cout << "   IV: ";
    print_hex(encrypted.iv);
    std::cout << "   Auth Tag: ";
    print_hex(encrypted.tag);
    std::cout << "\n";

    // Step 4: Encode ciphertext to Base64 for transmission
    std::cout << "4. Encoding to Base64 for transmission...\n";
    auto base64_result = encoding::base64::encode(encrypted.ciphertext);
    if (!base64_result) {
        std::cerr << "Base64 encoding failed\n";
        return 1;
    }
    std::string base64_str(reinterpret_cast<const char*>(base64_result->data()),
                          base64_result->size());
    std::cout << "   Base64: " << base64_str.substr(0, 64) << "...\n\n";

    // Step 5: Generate RSA key pair for signing
    std::cout << "5. Generating RSA-2048 key pair for digital signature...\n";
    auto rsa_key_result = asymmetric::rsa::generate_key_pair(2048);
    if (!rsa_key_result) {
        std::cerr << "RSA key generation failed\n";
        return 1;
    }
    auto rsa_key = std::move(*rsa_key_result);
    std::cout << "   Key pair generated ✓\n\n";

    // Step 6: Sign the encrypted data
    std::cout << "6. Signing encrypted data with RSA...\n";
    auto signature = asymmetric::rsa::sign(encrypted.ciphertext, rsa_key);
    if (!signature) {
        std::cerr << "Signing failed\n";
        return 1;
    }
    std::cout << "   Signature: ";
    print_hex(*signature);
    std::cout << "\n";

    std::cout << "--- Message prepared for transmission ---\n\n";

    // ====================================================================
    // Receiver side
    // ====================================================================

    std::cout << "=== Receiver Side ===\n\n";

    // Step 7: Verify signature
    std::cout << "7. Verifying RSA signature...\n";
    auto verify_result = asymmetric::rsa::verify(encrypted.ciphertext, *signature, rsa_key);
    if (!verify_result || !*verify_result) {
        std::cerr << "   Signature verification FAILED!\n";
        return 1;
    }
    std::cout << "   Signature verified ✓\n\n";

    // Step 8: Decode from Base64
    std::cout << "8. Decoding from Base64...\n";
    auto decoded_result = encoding::base64::decode(base64_str);
    if (!decoded_result) {
        std::cerr << "Base64 decoding failed\n";
        return 1;
    }
    std::cout << "   Decoded ✓\n\n";

    // Step 9: Decrypt with AES-256-GCM (with authentication)
    std::cout << "9. Decrypting with AES-256-GCM...\n";
    auto dec_result = cipher::aes_256_gcm::decrypt(
        encrypted, aes_key, std::as_bytes(std::span(aad))
    );
    if (!dec_result) {
        std::cerr << "   Decryption/Authentication FAILED!\n";
        std::cerr << "   Error: " << dec_result.error_value().message() << "\n";
        return 1;
    }
    std::cout << "   Authentication ✓\n";
    std::cout << "   Decryption ✓\n\n";

    std::string decrypted_message(reinterpret_cast<const char*>(dec_result->data()),
                                  dec_result->size());

    // Step 10: Verify hash
    std::cout << "10. Verifying message hash...\n";
    auto hash_verify = hash::sha256::hash(decrypted_message);
    if (!hash_verify) {
        std::cerr << "Hashing failed\n";
        return 1;
    }

    if (*hash_verify == *hash_result) {
        std::cout << "    Hash verified ✓\n\n";
    } else {
        std::cerr << "    Hash mismatch! Message may be corrupted!\n";
        return 1;
    }

    // Step 11: Final result
    std::cout << "11. Final Decrypted Message:\n";
    std::cout << "    " << decrypted_message << "\n\n";

    std::cout << "=== Workflow Complete ===\n";
    std::cout << "✓ Encryption (AES-256-GCM)\n";
    std::cout << "✓ Authentication (GCM tag)\n";
    std::cout << "✓ Digital Signature (RSA-2048)\n";
    std::cout << "✓ Hash Verification (SHA-256)\n";
    std::cout << "✓ Base64 Encoding\n";
    std::cout << "\nAll security checks passed!\n";

    return 0;
}
