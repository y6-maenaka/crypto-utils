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


inline const EVP_MD* get_evp_md( std::size_t HASH_TYPE )
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
  template < std::size_t HASH_TYPE, typename Container > static inline cu_result hash( const Container &input );
  template < std::size_t HASH_TYPE, typename T > static inline cu_result hash( const T *input, std::size_t input_size );
};


template < std::size_t HASH_TYPE, typename Container > inline cu_result sha2::hash( const Container &input )
{
  cu_result ret = cu_result::empty();

  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  const EVP_MD *md = get_evp_md( HASH_TYPE );
  if( md == nullptr ){
	EVP_MD_CTX_free( mdctx );
	return cu_result::empty();
  }
  std::size_t md_len = EVP_MD_size(md);

  if( EVP_DigestInit_ex( mdctx, md, nullptr) <= 0 ){
	EVP_MD_CTX_free( mdctx );
	return cu_result::empty();
  }

  if( EVP_DigestUpdate( mdctx, input.data(), input.size() ) <= 0  ){
	EVP_MD_CTX_free( mdctx );
	return cu_result::empty();
  }
  
  (*ret).resize( md_len ); 
  unsigned int out_len = 0;
  if( (EVP_DigestFinal_ex( mdctx, reinterpret_cast<unsigned char*>((*ret).data()), &out_len )) <= 0 || out_len <= 0 ){
	EVP_MD_CTX_free( mdctx );
	return cu_result::empty();
  }
 
  EVP_MD_CTX_free( mdctx );
  return ret;
}

template < std::size_t HASH_TYPE, typename T > inline cu_result sha2::hash( const T *input, std::size_t input_size )
{
  std::vector<std::byte> input_v = to_vector( input, input_size );
  return sha2::hash< HASH_TYPE >( input_v );
}


};


#endif // 


