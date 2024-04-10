#include "rsa_manager.h"

#include "../w_evp_pkey/evp_pkey.h"
#include "../w_sha/sha.h"


namespace openssl_wrapper
{
namespace rsa
{




std::size_t W_RSAManager::encrypt( evp_pkey::W_EVP_PKEY* wpkey , const unsigned char* plainBin , const std::size_t plainBinLength ,std::shared_ptr<unsigned char> *cipherBin )
{
  EVP_PKEY_CTX *pctx = nullptr;
  std::size_t outLength;

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

  if( EVP_PKEY_encrypt( pctx, nullptr,  &outLength, plainBin , plainBinLength  ) <= 0 )   // 暗号文サイズの取得
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }
   
  *cipherBin = std::shared_ptr<unsigned char>( new unsigned char[outLength] );
  if( EVP_PKEY_encrypt( pctx, (*cipherBin).get() ,  &outLength, plainBin , plainBinLength ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }

  return outLength;
}


std::size_t W_RSAManager::sign( evp_pkey::W_EVP_PKEY* wpkey , const unsigned char* plainBin , const std::size_t plainBinLength , std::shared_ptr<unsigned char> *signBin )
{
  std::size_t outLength = 0;
  std::shared_ptr<unsigned char> md; std::size_t mdLength;

  mdLength = sha::W_SHA::hash( plainBin , plainBinLength, &md , "sha256" );
  if( mdLength <= 0 || md == nullptr ) return 0;

  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new( wpkey->rawPkey() , nullptr );
  if( pctx == nullptr ) return 0;

  if( EVP_PKEY_sign_init( pctx ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }
  if( EVP_PKEY_sign( pctx , nullptr, &outLength, md.get(), mdLength  ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }
  
  *signBin = std::shared_ptr<unsigned char>( new unsigned char[outLength] );
  if( EVP_PKEY_sign( pctx , (*signBin).get(), &outLength , md.get(), mdLength ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }

  return outLength;
}


std::size_t W_RSAManager::decrypt( evp_pkey::W_EVP_PKEY* wpkey , const unsigned char* cipherBin , const std::size_t cipherBinLength ,std::shared_ptr<unsigned char> *plainBin )
{
  EVP_PKEY_CTX *pctx = nullptr;
  std::size_t outLength;

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

  if( EVP_PKEY_decrypt( pctx, nullptr,  &outLength, cipherBin , cipherBinLength ) <= 0 )   // 暗号文サイズの取得
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }
   
  *plainBin = std::shared_ptr<unsigned char>( new unsigned char[outLength] );
  if( EVP_PKEY_decrypt( pctx, (*plainBin).get() ,  &outLength, cipherBin , cipherBinLength ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return 0;
  }

  return outLength;
}


bool W_RSAManager::verify( evp_pkey::W_EVP_PKEY* wpkey , const unsigned char* signBin , const std::size_t signBinLength , const unsigned char* msgBin, const std::size_t msgBinLength )
{
  if( signBin == nullptr || signBinLength <= 0 ) return false;
  if( msgBin == nullptr || msgBinLength <= 0 ) return false;

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new( wpkey->rawPkey() , nullptr );
  if( pctx == nullptr ) return false;
  
  std::shared_ptr<unsigned char> msgDigest = nullptr; std::size_t msgDigestLength;
  msgDigestLength = sha::W_SHA::hash( msgBin, msgBinLength , &msgDigest , "sha256" );
  if( msgDigest == nullptr || msgDigestLength <= 0 )  return false;

  if( EVP_PKEY_verify_init( pctx ) <= 0 ){
	EVP_PKEY_CTX_free( pctx );
	return false;
  }

  int ret = EVP_PKEY_verify( pctx , (const unsigned char*)(signBin) , signBinLength , msgDigest.get() , msgDigestLength );

  EVP_PKEY_CTX_free( pctx );

  return ret == 1;
}




};
};
