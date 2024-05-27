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
#include "./common.hpp"


namespace cu
{


constexpr std::size_t AES_CBC_BLOCK_SIZE_BYTES = 16;
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
  template < std::size_t N, typename Container > static inline cu_result encrypt( const Container &plain, const aes::key<N> &key );
  template < std::size_t N, typename Container > static inline cu_result decrypt( const Container &cipher, const aes::key<N> &key );
  template < std::size_t N > static inline std::size_t get_encrypt_length( std::size_t plain_bin_length );
};

const EVP_CIPHER* get_evp_cipher(int n)
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

template < std::size_t N, typename Container> inline cu_result aes::encrypt( const Container &plain, const aes::key<N> &key )
{
  cu_result ret = cu_result::empty();

  EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();

  if( EVP_EncryptInit_ex( cctx, get_evp_cipher(N), nullptr, key.get_raw(), nullptr) <= 0 ) {
	EVP_CIPHER_CTX_free( cctx ); 
	return cu_result::empty();
  } 

  (*ret).resize( aes::get_encrypt_length<N>(plain.size()) );
  int unpadded_cipher_bin_len = 0;
  if( EVP_EncryptUpdate( cctx, reinterpret_cast<unsigned char*>(ret().data()), &unpadded_cipher_bin_len, reinterpret_cast<const unsigned char*>(plain.data()), plain.size() ) <= 0 ) {
	EVP_CIPHER_CTX_free( cctx );
	return cu_result::empty();
  }
  
  int padded_cipher_bin_len = 0;
  if( EVP_EncryptFinal_ex( cctx, reinterpret_cast<unsigned char*>(ret().data()) + unpadded_cipher_bin_len, &padded_cipher_bin_len ) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return cu_result::empty();
  }

  EVP_CIPHER_CTX_free( cctx );
  return ret;
}

template < std::size_t N, typename Container > inline cu_result aes::decrypt( const Container &cipher, const aes::key<N> &key )
{
  cu_result ret = cu_result::empty();

  EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();

  if( EVP_DecryptInit_ex( cctx, get_evp_cipher(N), nullptr,  key.get_raw(), nullptr ) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return cu_result::empty();
  }

  (*ret).resize( cipher.size() ); // 後でスライスする
  int unpadded_plain_len = 0;
  if( EVP_DecryptUpdate( cctx, reinterpret_cast<unsigned char*>((*ret).data()), &unpadded_plain_len, reinterpret_cast<const unsigned char*>(cipher.data()), cipher.size() ) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return cu_result::empty();
  }

  int padded_plain_len = 0;
  if( EVP_DecryptFinal( cctx, reinterpret_cast<unsigned char*>((*ret).data()) + unpadded_plain_len, &unpadded_plain_len) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return cu_result::empty();
  }

  (*ret).resize( padded_plain_len + unpadded_plain_len );
  return ret;
}

template< std::size_t N > inline std::size_t aes::get_encrypt_length( std::size_t plain_bin_length ) 
{
  static_assert( is_allowed_key_length(N) , "AES key length must be 128, 192 or 256 bits" );

  std::size_t ret = floor( plain_bin_length / AES_CBC_BLOCK_SIZE_BYTES ) * AES_CBC_BLOCK_SIZE_BYTES;
  return ret + AES_CBC_BLOCK_SIZE_BYTES;
}


};


#endif 


