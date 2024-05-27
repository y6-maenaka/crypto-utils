#ifndef DFD3C8A9_AFC5_4ED2_8605_08B1C1C105E9
#define DFD3C8A9_AFC5_4ED2_8605_08B1C1C105E9


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


class sha1
{
public:
  template < typename Container > static inline std::vector<std::byte> hash( const Container &input );
};


template < typename Container > inline std::vector<std::byte> sha1::hash( const Container &input )
{
  std::vector<std::byte> ret;

  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  const EVP_MD *md = EVP_get_digestbyname("sha1");
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

#endif 
