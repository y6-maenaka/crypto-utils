#ifndef C5D3220A_2E49_447F_974D_B8A0E140ED8E
#define C5D3220A_2E49_447F_974D_B8A0E140ED8E

#include <iostream>
#include <string>
#include <memory>
#include <vector>

#include "openssl/evp.h"


namespace cu
{


class w_sha
{
public:
  enum hash_t 
  {
	SHA1
	  , SHA256
	  , SHA516
  };
  
  static std::size_t hash( const unsigned char* from , const std::size_t fromLength , std::shared_ptr<unsigned char> *out , std::string type );
  template < typename T > static std::vector< std::uint8_t > hash( T *from, const std::size_t from_length, const hash_t &ht );
};


template < typename T > std::vector< std::uint8_t > w_sha::hash( T* from, const std::size_t from_length, const hash_t &ht )
{
  unsigned char from_r[from_length];
  std::memcpy( from_r, from, from_length );

  std::shared_ptr<unsigned char> md;
  std::size_t md_length = 0;
  switch( ht )
  {
	case w_sha::hash_t::SHA1 :
	  {
		md_length = w_sha::hash( from_r, from_length, &md, "sha1" );
		break;
	  }
	case w_sha::hash_t::SHA256 : 
	  {
		md_length = w_sha::hash( from_r, from_length, &md, "sha256" );
		break;
	  }
	case w_sha::hash_t::SHA516 :
	  {
		md_length = w_sha::hash( from_r, from_length, &md, "sha512" );
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


