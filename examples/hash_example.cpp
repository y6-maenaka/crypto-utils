#include <iostream>
#include <iomanip>
#include "../crypto_utils.hpp"

using namespace crypto_utils;

void print_hex(const core::byte_vector& data) {
    for (auto byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(byte);
    }
    std::cout << std::dec << "\n";
}

int main() {
    std::cout << "=== Hash Algorithm Examples ===\n\n";

    std::string message = "Hello, crypto_utils v2.0!";
    std::cout << "Message: " << message << "\n\n";

    // SHA-1
    {
        std::cout << "SHA-1:\n";
        auto result = hash::sha1::hash(message);
        if (result) {
            std::cout << "  Digest: ";
            print_hex(*result);
        } else {
            std::cerr << "  Error: " << result.error_value().message() << "\n";
        }
        std::cout << "\n";
    }

    // SHA-256
    {
        std::cout << "SHA-256:\n";
        auto result = hash::sha256::hash(message);
        if (result) {
            std::cout << "  Digest: ";
            print_hex(*result);
        } else {
            std::cerr << "  Error: " << result.error_value().message() << "\n";
        }
        std::cout << "\n";
    }

    // SHA-512
    {
        std::cout << "SHA-512:\n";
        auto result = hash::sha512::hash(message);
        if (result) {
            std::cout << "  Digest: ";
            print_hex(*result);
        } else {
            std::cerr << "  Error: " << result.error_value().message() << "\n";
        }
        std::cout << "\n";
    }

    // SHA3-256 (New!)
    {
        std::cout << "SHA3-256:\n";
        auto result = hash::sha3_256::hash(message);
        if (result) {
            std::cout << "  Digest: ";
            print_hex(*result);
        } else {
            std::cerr << "  Error: " << result.error_value().message() << "\n";
        }
        std::cout << "\n";
    }

    // Streaming hash example
    {
        std::cout << "SHA-256 Streaming API:\n";
        hash::sha256::streaming_context ctx;

        std::string part1 = "Hello, ";
        std::string part2 = "crypto_utils ";
        std::string part3 = "v2.0!";

        auto update1 = ctx.update(std::as_bytes(std::span(part1)));
        auto update2 = ctx.update(std::as_bytes(std::span(part2)));
        auto update3 = ctx.update(std::as_bytes(std::span(part3)));

        if (update1 && update2 && update3) {
            auto result = ctx.finalize();
            if (result) {
                std::cout << "  Digest: ";
                print_hex(*result);
            }
        }
        std::cout << "\n";
    }

    return 0;
}
