#ifndef F71D9744_2F6F_4A69_A671_C924DAC6E5CE
#define F71D9744_2F6F_4A69_A671_C924DAC6E5CE


#include <iostream>
#include <memory>
#include <algorithm>
#include <type_traits>

#include "openssl/rsa.h"
#include "openssl/engine.h"

#include "./evp_pkey.hpp"
#include "./sha2.hpp"
#include "./common.hpp"


namespace cu
{


class rsa
{
public:
  template < typename Container > static inline std::vector<std::byte> encrypt( evp_pkey *pkey, const Container &plain );
  template < typename Container > static inline std::vector<std::byte> sign( evp_pkey *pkey, const Container &plain );

  template < typename Container > static inline std::vector<std::byte> decrypt( evp_pkey *pkey, const Container &cipher );
  template < typename Container_1, typename Container_2 > static inline bool verify( evp_pkey *pkey, const Container_1 &sign, const Container_2 &plain );
};


template < typename Container > inline std::vector<std::byte> rsa::encrypt( evp_pkey *pkey, const Container &plain )
{
  if( pkey == nullptr ) return std::vector<std::byte>();

  std::vector<std::byte> ret;
  EVP_PKEY_CTX *pctx = nullptr;
  std::size_t out_len;

  if( (pctx = EVP_PKEY_CTX_new( pkey->get() , nullptr )) == nullptr ) return std::vector<std::byte>();

  if( EVP_PKEY_encrypt_init( pctx ) <= 0 ){
	EVP_PKEY_CTX_free( pctx );
	return std::vector<std::byte>();
  }

  if( EVP_PKEY_CTX_set_rsa_padding( pctx, RSA_PKCS1_OAEP_PADDING ) <= 0 ) {
	EVP_PKEY_CTX_free( pctx );
	return std::vector<std::byte>();
  }

  if( EVP_PKEY_encrypt( pctx, nullptr,  &out_len, reinterpret_cast<const unsigned char*>(plain.data()) , plain.size() ) <= 0 ) { // 暗号文サイズの取得
	EVP_PKEY_CTX_free( pctx );
	return std::vector<std::byte>();
  }
   
  ret.resize( out_len );
  if( EVP_PKEY_encrypt( pctx, reinterpret_cast<unsigned char*>(ret.data()) ,  &out_len, reinterpret_cast<const unsigned char*>(plain.data()) ,plain.size() ) <= 0 ) {
	EVP_PKEY_CTX_free( pctx );
	return std::vector<std::byte>();
  }

  ret.resize( out_len );
  return ret;
}

template < typename Container > inline std::vector<std::byte> rsa::sign( evp_pkey *pkey, const Container &plain )
{
  std::size_t out_len = 0;
  std::vector<std::byte> ret;
  EVP_PKEY_CTX *pctx = nullptr;

  auto md = sha2::hash<256>( plain );
  if( md.size() <= 0 ) return std::vector<std::byte>();

  if( (pctx = EVP_PKEY_CTX_new( pkey->get() , nullptr )) == nullptr ) return std::vector<std::byte>();

  if( (EVP_PKEY_sign_init( pctx )) <= 0 ){
	EVP_PKEY_CTX_free( pctx );
	return std::vector<std::byte>();
  }

  if( (EVP_PKEY_sign( pctx , nullptr, &out_len, reinterpret_cast<const unsigned char*>(md.data()), md.size() )) <= 0 ) {
	EVP_PKEY_CTX_free( pctx );
	return std::vector<std::byte>();
  }
 
  ret.resize( out_len );
  if( EVP_PKEY_sign( pctx , reinterpret_cast<unsigned char*>(ret.data()), &out_len , reinterpret_cast<const unsigned char*>(md.data()), md.size() ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return std::vector<std::byte>();
  }

  ret.resize( out_len );
  return ret ;
}

template < typename Container > inline std::vector<std::byte> rsa::decrypt( evp_pkey *pkey, const Container &cipher )
{
  if( pkey == nullptr ) return std::vector<std::byte>();

  std::vector<std::byte> ret;
  EVP_PKEY_CTX *pctx = nullptr;
  std::size_t out_len;

  if( (pctx = EVP_PKEY_CTX_new( pkey->get() , nullptr )) == nullptr ) return std::vector<std::byte>();

  if( EVP_PKEY_decrypt_init( pctx ) <= 0 ){
	EVP_PKEY_CTX_free( pctx );
	return std::vector<std::byte>();
  }

  if( EVP_PKEY_CTX_set_rsa_padding( pctx, RSA_PKCS1_OAEP_PADDING ) <= 0 ){
	EVP_PKEY_CTX_free( pctx );
	return std::vector<std::byte>();
  }

  if( EVP_PKEY_decrypt( pctx, nullptr,  &out_len, reinterpret_cast<const unsigned char*>(cipher.data()) , cipher.size() ) <= 0 ) { // 暗号文サイズの取得
	EVP_PKEY_CTX_free( pctx );
	return std::vector<std::byte>();
  }
   
  ret.resize( out_len );
  if( EVP_PKEY_decrypt( pctx, reinterpret_cast<unsigned char*>(ret.data()) ,  &out_len, reinterpret_cast<const unsigned char*>(cipher.data()) , cipher.size() ) <= 0 ) {
	EVP_PKEY_CTX_free( pctx );
	return std::vector<std::byte>();
  }

  ret.resize( out_len );
  return ret;
}

template < typename Container_1, typename Container_2 > inline bool rsa::verify( evp_pkey *pkey, const Container_1 &sign, const Container_2 &plain )
{
  if( pkey == nullptr || sign.size() <= 0 || plain.size() <= 0 ) return false;

  EVP_PKEY_CTX *pctx;
  if( (pctx = EVP_PKEY_CTX_new( pkey->get() , nullptr )) == nullptr ) return false;
 
  std::shared_ptr<unsigned char> msgDigest = nullptr; std::size_t msgDigestLength;
  auto md = sha2::hash<256>( plain );
  if( md.size() <= 0 ) return false;

  if( EVP_PKEY_verify_init( pctx ) <= 0 ){
	EVP_PKEY_CTX_free( pctx );
	return false;
  }

  int ret = EVP_PKEY_verify( pctx , reinterpret_cast<const unsigned char*>(sign.data()) , sign.size(), reinterpret_cast<const unsigned char*>(md.data()) , md.size() );

  EVP_PKEY_CTX_free( pctx );
  return ret == 1;
}


};


#endif 
