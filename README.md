# crypto_utils v2.0

Modern C++20 OpenSSL Wrapper Library - A comprehensive, type-safe cryptographic library built on OpenSSL 3.0+

[![C++](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0%2B-green.svg)](https://www.openssl.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## ✨ Features

### Hash Algorithms
- **SHA-1**: Legacy support (160-bit)
- **SHA-2 Family**: SHA-224, SHA-256, SHA-384, SHA-512
- **SHA-3 Family**: SHA3-224, SHA3-256, SHA3-384, SHA3-512 (FIPS 202)
- Streaming API for large data
- Unified interface with CRTP pattern

### Symmetric Ciphers
- **AES-CBC**: Block cipher with PKCS#7 padding
- **AES-CTR**: Counter mode (stream cipher, parallelizable)
- **AES-GCM**: Authenticated encryption (AEAD, recommended)
- Key sizes: 128, 192, 256 bits
- Automatic random IV/nonce generation
- Secure key generation

### Asymmetric Cryptography
- **RSA**: 2048/4096-bit encryption and digital signatures
- **ECDSA**: Elliptic curve signatures (secp256k1, P-256/384/521)
- PEM file I/O with optional password protection (AES-256-CBC)
- OAEP padding for RSA encryption
- SHA-256 based signatures

### Encoding
- **Base64**: RFC 4648 compliant encoding/decoding
- Binary-safe operations

### Core Features
- **RAII**: Automatic resource management for all OpenSSL objects
- **Error Handling**: C++23 `std::expected`-style `result<T>` type
- **Type Safety**: C++20 concepts for compile-time checks
- **Header-Only**: Easy integration
- **Exception-Free**: All errors returned via result types
- **Modern C++**: Leverages C++20 features (concepts, std::span, constexpr)

## 📋 Requirements

- **C++20** compatible compiler (GCC 10+, Clang 13+, MSVC 2019+)
- **OpenSSL 3.0+** (earlier versions not supported)
- **CMake 3.20+** (for building examples)

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/crypto_utils.git
cd crypto_utils

# Build examples
cmake -B build
cmake --build build

# Run examples
./build/examples/example_hash
./build/examples/example_cipher
./build/examples/example_asymmetric
```

### Basic Usage

#### Hash Calculation

```cpp
#include "crypto_utils.hpp"
using namespace crypto_utils;

// Simple hash
auto result = hash::sha256::hash("Hello, World!");
if (result) {
    const auto& digest = *result;  // std::vector<std::byte>
    // Use digest...
} else {
    std::cerr << "Error: " << result.error_value().message() << "\n";
}

// Streaming hash for large data
hash::sha256::streaming_context ctx;
ctx.update(chunk1);
ctx.update(chunk2);
auto digest = ctx.finalize();
```

#### AES Encryption (CBC Mode)

```cpp
using namespace crypto_utils;

// Generate random 256-bit key
auto key = cipher::aes_key<cipher::aes_key_size::aes_256>::generate_random();

// Encrypt
auto enc_result = cipher::aes_256_cbc::encrypt(plaintext, *key);
if (enc_result) {
    auto& enc = *enc_result;
    // enc.ciphertext and enc.iv must both be saved

    // Decrypt
    auto dec_result = cipher::aes_256_cbc::decrypt(enc, *key);
    if (dec_result) {
        // Decryption successful
    }
}
```

#### AES-GCM (Authenticated Encryption)

```cpp
using namespace crypto_utils;

auto key = cipher::aes_key<cipher::aes_key_size::aes_256>::generate_random();

// Optional additional authenticated data (not encrypted, but authenticated)
std::string aad = "header-info";

// Encrypt
auto enc_result = cipher::aes_256_gcm::encrypt(
    plaintext, *key, std::as_bytes(std::span(aad))
);
if (enc_result) {
    auto& enc = *enc_result;
    // Save enc.ciphertext, enc.iv, and enc.tag

    // Decrypt with authentication
    auto dec_result = cipher::aes_256_gcm::decrypt(
        enc, *key, std::as_bytes(std::span(aad))
    );
    if (!dec_result) {
        // Authentication failed - data was tampered with!
    }
}
```

#### RSA Encryption & Signatures

```cpp
using namespace crypto_utils;

// Generate 2048-bit RSA key pair
auto key_result = asymmetric::rsa::generate_key_pair(2048);
auto key_pair = *key_result;

// Save keys (private key encrypted with AES-256-CBC)
key_pair.save_public_key("public.pem");
key_pair.save_private_key("private.pem", "password");

// Encrypt
auto ciphertext = asymmetric::rsa::encrypt(message, key_pair);

// Decrypt
auto plaintext = asymmetric::rsa::decrypt(*ciphertext, key_pair);

// Sign
auto signature = asymmetric::rsa::sign(document, key_pair);

// Verify
auto verified = asymmetric::rsa::verify(document, *signature, key_pair);
if (verified && *verified) {
    std::cout << "Signature valid!\n";
}
```

#### ECDSA Signatures

```cpp
using namespace crypto_utils;

// Generate ECDSA key pair (P-256 curve)
auto key_result = asymmetric::ecdsa::generate_key_pair(
    asymmetric::ec_curve::secp256r1
);
auto key_pair = *key_result;

// Sign
auto signature = asymmetric::ecdsa::sign(message, key_pair);

// Verify
auto verified = asymmetric::ecdsa::verify(message, *signature, key_pair);
```

#### Base64 Encoding

```cpp
using namespace crypto_utils;

auto encoded = encoding::base64::encode(data);
auto decoded = encoding::base64::decode(*encoded);
```

## 📖 API Documentation

### Error Handling

All operations return `result<T>` which can be checked:

```cpp
auto result = hash::sha256::hash(data);

// Check if successful
if (result) {
    // Success - access value
    auto& value = *result;
}

// Check for errors
if (!result) {
    // Error occurred
    const auto& err = result.error_value();
    std::cerr << "Error: " << err.message() << "\n";
    std::cerr << "OpenSSL: " << err.openssl_error() << "\n";
}

// Alternative: use has_value()
if (result.has_value()) {
    auto& value = result.value();
}
```

### Supported Algorithms

| Category | Algorithm | Key Sizes | Notes |
|----------|-----------|-----------|-------|
| Hash | SHA-1 | - | Legacy, not recommended |
| Hash | SHA-2 | - | SHA-224/256/384/512 |
| Hash | SHA-3 | - | SHA3-224/256/384/512 (FIPS 202) |
| Cipher | AES-CBC | 128/192/256 | PKCS#7 padding |
| Cipher | AES-CTR | 128/192/256 | Stream cipher mode |
| Cipher | AES-GCM | 128/192/256 | AEAD, recommended |
| Asymmetric | RSA | 2048/4096 | OAEP padding, SHA-256 |
| Asymmetric | ECDSA | - | secp256k1, P-256/384/521 |
| Encoding | Base64 | - | RFC 4648 |

## 🔒 Security Considerations

### ✅ Best Practices Implemented

1. **Random IV/Nonce Generation**: Every encryption uses a cryptographically secure random IV
2. **Authenticated Encryption**: AES-GCM provides both confidentiality and authenticity
3. **Secure Padding**: OAEP for RSA, PKCS#7 for CBC mode
4. **Modern Algorithms**: SHA-3, AES-GCM, ECDSA support
5. **No Deprecated APIs**: All OpenSSL 3.0+ modern APIs
6. **Key Protection**: Private keys encrypted with AES-256-CBC (not 3DES)

### ⚠️ Important Notes

- **SHA-1**: Deprecated for security-critical applications (collision attacks). Use SHA-256 or SHA-3.
- **Key Management**: Securely store and manage encryption keys. This library does not provide key management.
- **Password Storage**: Never encrypt passwords - use proper password hashing (bcrypt, argon2, etc.)
- **Random Number Generation**: Uses OpenSSL's CSPRNG (`RAND_bytes`)

## 📁 Project Structure

```
crypto_utils/
├── crypto_utils.hpp              # Main header (include this)
├── include/crypto_utils/
│   ├── core/                     # Core infrastructure
│   │   ├── openssl_ptr.hpp       # RAII wrappers
│   │   ├── error.hpp             # Error codes & info
│   │   ├── result.hpp            # result<T> type
│   │   └── concepts.hpp          # C++20 concepts
│   ├── hash/                     # Hash algorithms
│   │   ├── hash_algorithm.hpp    # Unified interface
│   │   ├── sha1.hpp
│   │   ├── sha2.hpp
│   │   └── sha3.hpp
│   ├── cipher/                   # Symmetric ciphers
│   │   ├── aes_common.hpp
│   │   ├── aes_cbc.hpp
│   │   ├── aes_ctr.hpp
│   │   └── aes_gcm.hpp
│   ├── asymmetric/               # Public-key crypto
│   │   ├── key_pair.hpp
│   │   ├── rsa.hpp
│   │   └── ecdsa.hpp
│   └── encoding/
│       └── base64.hpp
├── examples/                     # Usage examples
└── CMakeLists.txt
```

## 🔄 Migration from v1.x

### Breaking Changes

| v1.x | v2.0 | Notes |
|------|------|-------|
| `cu::sha2::hash<256>(...)` | `crypto_utils::hash::sha256::hash(...)` | Namespace & API change |
| `cu_result` | `result<byte_vector>` | New error handling |
| `result.is_invalid()` | `!result` or `!result.has_value()` | Inverted logic |
| AES with fixed IV | AES with random IV per encryption | **Security fix** |
| 3DES key encryption | AES-256-CBC key encryption | Security improvement |

### Key Differences

1. **Namespace**: `cu::` → `crypto_utils::`
2. **Error Handling**: Boolean returns → `result<T>` with detailed errors
3. **AES IV**: Now returns `encrypted_data{ciphertext, iv}` - both must be saved
4. **Type Safety**: C++20 concepts enforce correct types at compile time
5. **Header Location**: Single `crypto_utils.hpp` includes everything

See detailed migration guide for step-by-step instructions.

## 🛠️ Building

### As a Header-Only Library

```cpp
// Just include the main header
#include "crypto_utils.hpp"

// Link against OpenSSL
// g++ -std=c++20 your_app.cpp -lssl -lcrypto
```

### With CMake

```cmake
find_package(crypto_utils REQUIRED)
target_link_libraries(your_target PRIVATE crypto_utils::crypto_utils)
```

### Examples

```bash
cmake -B build -DBUILD_EXAMPLES=ON
cmake --build build
./build/examples/example_full_workflow
```

## 📊 Performance

- **RAII Overhead**: Negligible - modern compilers optimize away wrapper costs
- **AES-GCM**: Faster than CBC + HMAC for authenticated encryption
- **ECDSA**: Smaller keys and faster signing than RSA
- **Streaming API**: Efficient for large files (no memory spikes)

## 🤝 Contributing

Contributions welcome! Please:

1. Follow existing code style (C++20, RAII, error handling via result<T>)
2. Add tests for new features
3. Update documentation
4. Ensure OpenSSL 3.0+ compatibility

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- Built on [OpenSSL](https://www.openssl.org/) 3.0+
- Inspired by modern C++ best practices
- CRTP pattern from Boost and other modern C++ libraries

## 📮 Contact

- Issues: [GitHub Issues](https://github.com/yourusername/crypto_utils/issues)
- Documentation: [Full API Docs](https://yourusername.github.io/crypto_utils/)

---

**crypto_utils v2.0** - Secure, Modern, Type-Safe Cryptography for C++20
