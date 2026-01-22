#include <iostream>
#include <iomanip>
#include "../crypto_utils.hpp"

using namespace crypto_utils;

int main() {
    std::cout << "=== Base64 Encoding Example ===\n\n";

    // Text encoding
    {
        std::string plaintext = "Hello, Base64!";
        std::cout << "Original text: " << plaintext << "\n";

        auto encoded = encoding::base64::encode(plaintext);
        if (!encoded) {
            std::cerr << "Encoding failed\n";
            return 1;
        }

        std::string encoded_str(reinterpret_cast<const char*>(encoded->data()),
                               encoded->size());
        std::cout << "Base64 encoded: " << encoded_str << "\n";

        auto decoded = encoding::base64::decode(*encoded);
        if (!decoded) {
            std::cerr << "Decoding failed\n";
            return 1;
        }

        std::string decoded_str(reinterpret_cast<const char*>(decoded->data()),
                               decoded->size());
        std::cout << "Decoded: " << decoded_str << "\n";
        std::cout << "Match: " << (decoded_str == plaintext ? "✓" : "✗") << "\n\n";
    }

    // Binary data encoding
    {
        core::byte_vector binary_data = {
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0xFF}, std::byte{0xFE}, std::byte{0xFD}, std::byte{0xFC}
        };

        std::cout << "Binary data (hex): ";
        for (auto byte : binary_data) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(byte);
        }
        std::cout << std::dec << "\n";

        auto encoded = encoding::base64::encode(binary_data);
        if (!encoded) {
            std::cerr << "Encoding failed\n";
            return 1;
        }

        std::string encoded_str(reinterpret_cast<const char*>(encoded->data()),
                               encoded->size());
        std::cout << "Base64 encoded: " << encoded_str << "\n";

        auto decoded = encoding::base64::decode(*encoded);
        if (!decoded) {
            std::cerr << "Decoding failed\n";
            return 1;
        }

        std::cout << "Decoded (hex): ";
        for (auto byte : *decoded) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(byte);
        }
        std::cout << std::dec << "\n";
        std::cout << "Match: " << (*decoded == binary_data ? "✓" : "✗") << "\n";
    }

    return 0;
}
