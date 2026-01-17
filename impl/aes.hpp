#ifndef B9839E16_5691_47CB_B6D4_E8C6D20BF974
#define B9839E16_5691_47CB_B6D4_E8C6D20BF974


#include <iostream>
#include <string>
#include <array>
#include <memory>
#include <cmath>
#include <algorithm>
#include <type_traits>

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/rand.h"
#include "./common.hpp"


namespace cu
{


constexpr std::size_t AES_CBC_BLOCK_SIZE_BYTES = 16;
constexpr std::size_t AES_CBC_IV_SIZE_BYTES = 16;
constexpr std::size_t AES_CBC_128_KEY_LENGTH_BYTES = 16;
constexpr std::size_t AES_CBC_192_KEY_LENGTH_BYTES = 24;
constexpr std::size_t AES_CBC_256_KEY_LENGTH_BYTES = 32;

constexpr bool is_allowed_key_length(std::size_t n) { // 指定した鍵長が許可されている長さか?
  return (( n == AES_CBC_128_KEY_LENGTH_BYTES || n == AES_CBC_192_KEY_LENGTH_BYTES || n == AES_CBC_256_KEY_LENGTH_BYTES ));
}

template< typename Container, std::size_t N > constexpr bool is_allowed_container() { // 指定した鍵の作成元が許可されているデータタイプか?
  return (
	std::is_same_v< Container, std::vector<std::byte>> 
	|| std::is_same_v< Container, std::array<std::byte, N>> 
	|| std::is_same_v< Container, std::array<std::uint8_t, N>>
	|| std::is_same_v< Container, std::vector<std::uint8_t> >
	|| std::is_same_v< Container, std::string> 
  );
}


class aes
{
public:
  using value_type = std::byte;

  // Encrypted data structure (IV || ciphertext)
  struct encrypted_data {
	std::vector<std::byte> iv;
	std::vector<std::byte> ciphertext;
  };

  template< std::size_t N > class key
  {
	public:
	  template < typename Container > key( const Container &key_from_c );
	  inline const std::uint8_t* get_raw() const;
	  inline void print() const;

	private:
	  std::array< value_type, N > _body;
  };

public:
  // New secure API with random IV
  template < std::size_t N, typename Container > static inline encrypted_data encrypt_secure( const Container &plain, const aes::key<N> &key );
  template < std::size_t N > static inline cu_result decrypt_secure( const encrypted_data &enc_data, const aes::key<N> &key );

  // Legacy API (kept for compatibility, but IV is now random - returns IV || ciphertext)
  template < std::size_t N, typename Container > static inline cu_result encrypt( const Container &plain, const aes::key<N> &key );
  template < std::size_t N, typename Container > static inline cu_result decrypt( const Container &cipher, const aes::key<N> &key );
  template < std::size_t N > static inline std::size_t get_encrypt_length( std::size_t plain_bin_length );
};

inline const EVP_CIPHER* get_evp_cipher(int n)
{
  switch(n)
  {
	case 16: return EVP_aes_128_cbc();
	case 24: return EVP_aes_192_cbc();
	case 32: return EVP_aes_256_cbc();
	default: return nullptr;
  }
}

template < std::size_t N >
template < typename Container >
aes::key<N>::key( const Container &key_from_c ) // only support CBC mode
{
  static_assert( is_allowed_container<Container, N>(),"Invalid key container type");
  if( key_from_c.size() != N ) throw std::invalid_argument("Invalid key size");
  std::transform( key_from_c.begin(), key_from_c.end(), _body.begin(), [](const char& cc){
	  return std::byte(cc);
	  } );
}

template < std::size_t N > inline const std::uint8_t* aes::key<N>::get_raw() const
{
  return reinterpret_cast<const std::uint8_t*>(_body.data());
}

template < std::size_t N > inline void aes::key<N>::print() const
{
  std::cout << "[ key length ] : " << N << "\n";

  std::cout << "[ key hex ] : 0x"; 
  for( auto &itr : _body ) printf("%02hhx", itr ); 
  std::cout << "\n";
}

// New secure encryption with random IV
template < std::size_t N, typename Container> inline aes::encrypted_data aes::encrypt_secure( const Container &plain, const aes::key<N> &key )
{
  encrypted_data result;

  // Generate random IV
  result.iv.resize(AES_CBC_IV_SIZE_BYTES);
  if( RAND_bytes(reinterpret_cast<unsigned char*>(result.iv.data()), AES_CBC_IV_SIZE_BYTES) != 1 ) {
	// RAND_bytes failed, return empty
	return result;
  }

  EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
  if( !cctx ) {
	result.iv.clear();
	return result;
  }

  if( EVP_EncryptInit_ex( cctx, get_evp_cipher(N), nullptr, key.get_raw(), reinterpret_cast<unsigned char*>(result.iv.data())) <= 0 ) {
	EVP_CIPHER_CTX_free( cctx );
	result.iv.clear();
	return result;
  }

  result.ciphertext.resize( aes::get_encrypt_length<N>(plain.size()) );
  int unpadded_cipher_bin_len = 0;
  if( EVP_EncryptUpdate( cctx, reinterpret_cast<unsigned char*>(result.ciphertext.data()), &unpadded_cipher_bin_len, reinterpret_cast<const unsigned char*>(plain.data()), plain.size() ) <= 0 ) {
	EVP_CIPHER_CTX_free( cctx );
	result.iv.clear();
	result.ciphertext.clear();
	return result;
  }

  int padded_cipher_bin_len = 0;
  if( EVP_EncryptFinal_ex( cctx, reinterpret_cast<unsigned char*>(result.ciphertext.data()) + unpadded_cipher_bin_len, &padded_cipher_bin_len ) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	result.iv.clear();
	result.ciphertext.clear();
	return result;
  }

  result.ciphertext.resize(unpadded_cipher_bin_len + padded_cipher_bin_len);
  EVP_CIPHER_CTX_free( cctx );
  return result;
}

// Legacy API - now returns (IV || ciphertext) concatenated
template < std::size_t N, typename Container> inline cu_result aes::encrypt( const Container &plain, const aes::key<N> &key )
{
  cu_result ret = cu_result::empty();

  auto enc_data = encrypt_secure<N>(plain, key);
  if( enc_data.iv.empty() || enc_data.ciphertext.empty() ) {
	return cu_result::empty();
  }

  // Concatenate IV and ciphertext: (IV || ciphertext)
  (*ret).reserve(enc_data.iv.size() + enc_data.ciphertext.size());
  (*ret).insert((*ret).end(), enc_data.iv.begin(), enc_data.iv.end());
  (*ret).insert((*ret).end(), enc_data.ciphertext.begin(), enc_data.ciphertext.end());

  return ret;
}

// New secure decryption with separate IV
template < std::size_t N > inline cu_result aes::decrypt_secure( const encrypted_data &enc_data, const aes::key<N> &key )
{
  cu_result ret = cu_result::empty();

  if( enc_data.iv.size() != AES_CBC_IV_SIZE_BYTES ) {
	return cu_result::empty();
  }

  EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
  if( !cctx ) {
	return cu_result::empty();
  }

  if( EVP_DecryptInit_ex( cctx, get_evp_cipher(N), nullptr, key.get_raw(), reinterpret_cast<const unsigned char*>(enc_data.iv.data()) ) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return cu_result::empty();
  }

  (*ret).resize( enc_data.ciphertext.size() );
  int unpadded_plain_len = 0;
  if( EVP_DecryptUpdate( cctx, reinterpret_cast<unsigned char*>((*ret).data()), &unpadded_plain_len, reinterpret_cast<const unsigned char*>(enc_data.ciphertext.data()), enc_data.ciphertext.size() ) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return cu_result::empty();
  }

  int padded_plain_len = 0;
  if( EVP_DecryptFinal_ex( cctx, reinterpret_cast<unsigned char*>((*ret).data()) + unpadded_plain_len, &padded_plain_len) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return cu_result::empty();
  }

  (*ret).resize( unpadded_plain_len + padded_plain_len );
  EVP_CIPHER_CTX_free( cctx );
  return ret;
}

// Legacy API - expects (IV || ciphertext) concatenated
template < std::size_t N, typename Container > inline cu_result aes::decrypt( const Container &cipher, const aes::key<N> &key )
{
  // Extract IV from the first 16 bytes
  if( cipher.size() < AES_CBC_IV_SIZE_BYTES ) {
	return cu_result::empty();
  }

  encrypted_data enc_data;
  enc_data.iv.resize(AES_CBC_IV_SIZE_BYTES);
  std::copy_n(reinterpret_cast<const std::byte*>(cipher.data()), AES_CBC_IV_SIZE_BYTES, enc_data.iv.begin());

  // Rest is ciphertext
  std::size_t ciphertext_size = cipher.size() - AES_CBC_IV_SIZE_BYTES;
  enc_data.ciphertext.resize(ciphertext_size);
  std::copy_n(reinterpret_cast<const std::byte*>(cipher.data()) + AES_CBC_IV_SIZE_BYTES, ciphertext_size, enc_data.ciphertext.begin());

  return decrypt_secure<N>(enc_data, key);
}

template< std::size_t N > inline std::size_t aes::get_encrypt_length( std::size_t plain_bin_length ) 
{
  static_assert( is_allowed_key_length(N) , "AES key length must be 128, 192 or 256 bits" );

  std::size_t ret = floor( plain_bin_length / AES_CBC_BLOCK_SIZE_BYTES ) * AES_CBC_BLOCK_SIZE_BYTES;
  return ret + AES_CBC_BLOCK_SIZE_BYTES;
}


};


#endif 


