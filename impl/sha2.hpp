#ifndef C5D3220A_2E49_447F_974D_B8A0E140ED8E
#define C5D3220A_2E49_447F_974D_B8A0E140ED8E


#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <algorithm>
#include <type_traits>

#include "openssl/evp.h"
#include "./common.hpp"


namespace cu
{


constexpr std::size_t SHA224 = 224;
constexpr std::size_t SHA256 = 256;
constexpr std::size_t SHA384 = 384;
constexpr std::size_t SHA512 = 512;

const EVP_MD* get_evp_md( std::size_t HASH_TYPE )
{
  switch( HASH_TYPE )
  {
	case SHA224: return EVP_get_digestbyname( "sha224");
	case SHA256: return EVP_get_digestbyname("sha256");
	case SHA384: return EVP_get_digestbyname("sha384");
	case SHA512: return EVP_get_digestbyname("sha512");
	default: return nullptr;
  }
}


class sha2
{
public:
  template < std::size_t HASH_TYPE ,typename Container > static inline std::vector<std::byte> hash( const Container &input );
};


template < std::size_t HASH_TYPE, typename Container > inline std::vector<std::byte> sha2::hash( const Container &input )
{
  std::vector<std::byte> ret;

  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  const EVP_MD *md = get_evp_md( HASH_TYPE );
  if( md == nullptr ){
	EVP_MD_CTX_free( mdctx );
	return std::vector<std::byte>();
  }
  std::size_t md_len = EVP_MD_size(md);

  if( EVP_DigestInit_ex( mdctx, md, nullptr) <= 0 ){
	EVP_MD_CTX_free( mdctx );
	return std::vector<std::byte>();
  }

  if( EVP_DigestUpdate( mdctx, input.data(), input.size() ) <= 0  ){
	EVP_MD_CTX_free( mdctx );
	return std::vector<std::byte>();
  }
  
  ret.resize( md_len ); 
  unsigned int out_len = 0;
  if( (EVP_DigestFinal_ex( mdctx, reinterpret_cast<unsigned char*>(ret.data()), &out_len )) <= 0 || out_len <= 0 ){
	EVP_MD_CTX_free( mdctx );
	return std::vector<std::byte>();
  }
 
  EVP_MD_CTX_free( mdctx );
  return ret;
}


};


#endif // 


