#ifndef C5D3220A_2E49_447F_974D_B8A0E140ED8E
#define C5D3220A_2E49_447F_974D_B8A0E140ED8E

#include <iostream>
#include <string>
#include <memory>
#include <vector>

#include "openssl/evp.h"


namespace cu
{


class sha
{
public:
  enum hash_t 
  {
	SHA1
	  , SHA256
	  , SHA516
  };
  
  static inline std::size_t hash( const unsigned char* from , const std::size_t fromLength , std::shared_ptr<unsigned char> *out , std::string type );
  template < typename T > static inline std::vector< std::uint8_t > hash( T *from, const std::size_t from_length, const hash_t &ht );
};


std::size_t sha::hash( const unsigned char* from , const std::size_t fromLength , std::shared_ptr<unsigned char> *out , std::string type )
{
  const EVP_MD *md;
  std::size_t outLength = 0;

  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  md = EVP_get_digestbyname( type.c_str() );
  *out = std::shared_ptr<unsigned char>( new unsigned char[EVP_MD_size(md)] );

  if( EVP_DigestInit_ex( mdctx , md, nullptr ) <= 0 )
  {
	EVP_MD_CTX_free( mdctx );
	return 0;
  }

  if( EVP_DigestUpdate( mdctx, from , fromLength ) <= 0 )
  {
	EVP_MD_CTX_free( mdctx );
	return 0;
  }

  if( EVP_DigestFinal_ex( mdctx , (*out).get(),  (unsigned int *)&outLength ) <= 0 )
  {
	EVP_MD_CTX_free( mdctx );
	return 0;
  }

  EVP_MD_CTX_free( mdctx );
  return outLength;
}

template < typename T > std::vector< std::uint8_t > sha::hash( T* from, const std::size_t from_length, const hash_t &ht )
{
  unsigned char from_r[from_length];
  std::memcpy( from_r, from, from_length );

  std::shared_ptr<unsigned char> md;
  std::size_t md_length = 0;
  switch( ht )
  {
	case sha::hash_t::SHA1 :
	  {
		md_length = sha::hash( from_r, from_length, &md, "sha1" );
		break;
	  }
	case sha::hash_t::SHA256 : 
	  {
		md_length = sha::hash( from_r, from_length, &md, "sha256" );
		break;
	  }
	case sha::hash_t::SHA516 :
	  {
		md_length = sha::hash( from_r, from_length, &md, "sha512" );
		break;
	  }
	default :
	  {
		return std::vector<std::uint8_t>();
	  }
  }
  
  std::vector< std::uint8_t > ret( md.get(), md.get() + md_length );
  return ret;
}


};


#endif // 


