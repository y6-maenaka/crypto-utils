<h1>crypto-utils: An OpenSSL Wrapper</h1>
crypto-utils is a C++ library providing a collection of utilities for cryptographic operations. Serving as a wrapper for the OpenSSL Toolkit, it offers functionalities such as generating message digests using SHA2, AES encryption and decryption (CBC mode), Base64 encoding and decoding, RSA encryption, decryption, signing, and verification, as well as operations with EVP_PKEY structures.

<hr>

<h2>0. Installation</h2>

```cpp
#include <crypto_utils.hpp>
```

<hr>

<h2>1. SHA2</h2>
 
```cpp
std::string plain; // Use std::array< std::uint8_t, N>, std::vector<char> etc...

/* Generate message digest */
auto md224 = cu::sha2::hash<224>(plain);
auto md256 = cu::sha2::hash<256>(plain);
auto md384 = cu::sha2::hash<384>(plain);
auto md512 = cu::sha2::hash<512>(plain);
```

<hr>

<h2>2. AES(only CBC)</h2>

```cpp
std::string key_from = "ABCDEFGHIJKLMNOP"; // Use std::array< std::uint8_t, N >. std::vector<char> etc...\

/* Generate AES key */
cu::aes::key<16> key( key_from );

/* Encrypt */
auto cipher: auto = cu::aes::encrypt<16>( plain_str, key );
/* Decrypt */
auto plain: auto = cu::aes::decrypt<16>( cipher, key );

// ※ Allowed key lengths: 16, 24, 32 [bytes]
```

<hr>

<h2>3. Base64</h2>
 
```cpp
std::string plain = "HelloWorld"; // Use std::array< std::uint8_t, N >. std::vector<char> etc...\

/* Encode */
auto encoded = cu::base64::encode( plain );
/* Decode */
auto decoded = u::base64::decode( encoded );
```

<hr>

<h2>4. RSA</h2>

```cpp
std::string plain = "HelloWorld"; // Use std::array< std::uint8_t, N >. std::vector<char> etc...\

/* Generat evp_pkey */
cu::evp_pkey pkey = cu::generate_rsa_evp_pkey( 4096 );

/* Encrypt */
auto cipher = cu::rsa::encrypt( &pkey, plain );
/* Decrypt */
auto decrypted = cu::rsa::decrypt( &pkey, cipher );

/* Sign */
auto sign = cu::rsa::sign( &pkey, plain );
/* Verity */
bool verification = cu::rsa::verify( &pkey, sign, plain );
```

<hr>

<h2>5. EVP_PKEY</h2>

```cpp
/* Generate evp_pkey */
cu::evp_pkey pkey = cu::evp_pkey::empty();
cu::evp_pkey pkey = cu::generate_rsa_evp_pkey( 4096 );

/* Save evp_pkey( private and public ) */
bool saved_pub = pkey.save_pubkey( "./pub.pem" );
bool saved_pri = pkey.save_prikey( "./pri.pem", "pass" );

/* Load evp_pkey( private and public ) */
bool loaded_pub = pkey.load_pubkey( "./pub.pem" );
bool loaded_pri = pkey.load_prikey( "./pri.pem", "pass" );
```

<hr> 

<h2>License</h2>
<p>This product includes software developed by the OpenSSL Project for use in the <a href="https://www.openssl.org/">OpenSSL Toolkit</a>.</p>
<p>Copyright (c) 1998-2011 The OpenSSL Project. All rights reserved.</p>
