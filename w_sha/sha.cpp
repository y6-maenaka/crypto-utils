#include "sha.h"


namespace openssl_wrapper
{
namespace sha
{





std::size_t W_SHA::hash( const unsigned char* from , const std::size_t fromLength , std::shared_ptr<unsigned char> *out , std::string type )
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





};
};

