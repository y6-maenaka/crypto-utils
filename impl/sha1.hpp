#ifndef DFD3C8A9_AFC5_4ED2_8605_08B1C1C105E9
#define DFD3C8A9_AFC5_4ED2_8605_08B1C1C105E9


#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <algorithm>
#include <type_traits>

#include "openssl/evp.h"
#include "./result.hpp"


namespace cu
{


class sha1
{
public:
  template < typename Container > static inline cu_result hash( const Container &input );
};


template < typename Container > inline cu_result sha1::hash( const Container &input )
{
  cu_result ret = cu_result::empty();

  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  const EVP_MD *md = EVP_get_digestbyname("sha1");
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



};

#endif 
