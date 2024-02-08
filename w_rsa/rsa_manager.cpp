#include "rsa_manager.h"

#include "../w_evp_pkey/evp_pkey.h"


namespace openssl_wrapper
{
namespace rsa
{




size_t W_RSAManager::encrypt( evp_pkey::W_EVP_PKEY* wpkey , unsigned char* from , size_t fromLength ,std::shared_ptr<unsigned char> *out )
{
  EVP_PKEY_CTX *pctx = nullptr;
  size_t outLength;

  pctx = EVP_PKEY_CTX_new( wpkey->rawPkey() , nullptr );
  if( pctx == nullptr ) return 0;

  if( EVP_PKEY_encrypt_init( pctx ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }

  if( EVP_PKEY_CTX_set_rsa_padding( pctx, RSA_PKCS1_OAEP_PADDING ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }

  if( EVP_PKEY_encrypt( pctx, nullptr,  &outLength, from , fromLength ) <= 0 )   // 暗号文サイズの取得
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }
   
  *out = std::shared_ptr<unsigned char>( new unsigned char[outLength] );
  if( EVP_PKEY_encrypt( pctx, (*out).get() ,  &outLength, from , fromLength ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }

  return outLength;
}


size_t W_RSAManager::decrypt( evp_pkey::W_EVP_PKEY* wpkey , unsigned char* from , size_t fromLength ,std::shared_ptr<unsigned char> *out )
{
  EVP_PKEY_CTX *pctx = nullptr;
  size_t outLength;

  pctx = EVP_PKEY_CTX_new( wpkey->rawPkey() , nullptr );
  if( pctx == nullptr ) return 0;

  if( EVP_PKEY_decrypt_init( pctx ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }

  if( EVP_PKEY_CTX_set_rsa_padding( pctx, RSA_PKCS1_OAEP_PADDING ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }

  if( EVP_PKEY_decrypt( pctx, nullptr,  &outLength, from , fromLength ) <= 0 )   // 暗号文サイズの取得
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }
   
  *out = std::shared_ptr<unsigned char>( new unsigned char[outLength] );
  if( EVP_PKEY_decrypt( pctx, (*out).get() ,  &outLength, from , fromLength ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }

  return outLength;

}

/*
void W_RSAManager::decrypt()
{
  return;
}
*/




};
};
