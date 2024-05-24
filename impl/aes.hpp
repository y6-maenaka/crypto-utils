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


template < std::size_t N >
class aes_key
{
  static_assert( is_allowed_key_length(N) , "AES key length must be 128, 192 or 256 bits" );
private:
  std::array< std::byte, N > _key;


public:
  template < typename Container > aes_key( const Container &key_from_c );
  inline const std::uint8_t* get_raw() const;

  inline void print() const;
};

class aes_manager
{
public:
  template < std::size_t N, typename Container > static inline std::vector<std::byte> encrypt( const Container &input, const aes_key<N> &key );
  template < std::size_t N, typename Container > static inline std::vector<std::byte> decrypt( const Container &input, const aes_key<N> &key );
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
aes_key<N>::aes_key( const Container &key_from_c ) // only support CBC mode
{
  static_assert( is_allowed_container<Container, N>(),"Invalid key container type");
  if( key_from_c.size() != N ) throw std::invalid_argument("Invalid key size");
  std::transform( key_from_c.begin(), key_from_c.end(), _key.begin(), [](const char& cc){
	  return std::byte(cc);
	  } );
}

template < std::size_t N > inline const std::uint8_t* aes_key<N>::get_raw() const
{
  return reinterpret_cast<const std::uint8_t*>(_key.data());
}

template < std::size_t N > inline void aes_key<N>::print() const
{
  std::cout << "[ key length ] : " << N << "\n";

  std::cout << "[ key hex ] : 0x"; 
  for( auto &itr : _key ) printf("%02hhx", itr ); 
  std::cout << "\n";
}

template < std::size_t N, typename Container> inline std::vector<std::byte> aes_manager::encrypt( const Container &input, const aes_key<N> &key )
{
  std::vector<std::byte> ret; 

  EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();

  if( EVP_EncryptInit_ex( cctx, get_evp_cipher(N), nullptr, key.get_raw(), nullptr) <= 0 ) {
	EVP_CIPHER_CTX_free( cctx ); 
	return std::vector<std::byte>();
  } 

  ret.resize( aes_manager::get_encrypt_length<N>(input.size()) );
  int unpadded_cipher_bin_len = 0;
  if( EVP_EncryptUpdate( cctx, reinterpret_cast<unsigned char*>(ret.data()), &unpadded_cipher_bin_len, reinterpret_cast<const unsigned char*>(input.data()), input.size() ) <= 0 ) {
	EVP_CIPHER_CTX_free( cctx );
	return std::vector<std::byte>();
  }
  
  int padded_cipher_bin_len = 0;
  if( EVP_EncryptFinal_ex( cctx, reinterpret_cast<unsigned char*>(ret.data()) + unpadded_cipher_bin_len, &padded_cipher_bin_len ) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return std::vector<std::byte>();
  }

  EVP_CIPHER_CTX_free( cctx );
  return ret;
}

template < std::size_t N, typename Container > inline std::vector<std::byte> aes_manager::decrypt( const Container &input, const aes_key<N> &key )
{
  std::vector<std::byte> ret;

  EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();

  if( EVP_DecryptInit_ex( cctx, get_evp_cipher(N), nullptr,  key.get_raw(), nullptr ) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return std::vector<std::byte>();
  }

  ret.resize( input.size() ); // 後でスライスする
  int unpadded_plain_len = 0;
  if( EVP_DecryptUpdate( cctx, reinterpret_cast<unsigned char*>(ret.data()), &unpadded_plain_len, reinterpret_cast<const unsigned char*>(input.data()), input.size() ) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return std::vector<std::byte>();
  }

  int padded_plain_len = 0;
  if( EVP_DecryptFinal( cctx, reinterpret_cast<unsigned char*>(ret.data()) + unpadded_plain_len, &unpadded_plain_len) <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return std::vector<std::byte>();
  }

  ret.resize( padded_plain_len + unpadded_plain_len );
  return ret;
}

template< std::size_t N > inline std::size_t aes_manager::get_encrypt_length( std::size_t plain_bin_length ) 
{
  static_assert( is_allowed_key_length(N) , "AES key length must be 128, 192 or 256 bits" );

  std::size_t ret = floor( plain_bin_length / AES_CBC_BLOCK_SIZE_BYTES ) * AES_CBC_BLOCK_SIZE_BYTES;
  return ret + AES_CBC_BLOCK_SIZE_BYTES;
}


};


#endif 


