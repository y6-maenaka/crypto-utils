#ifndef AF2FE8B7_66AC_46E4_A2C1_CB3E48AF9BA1
#define AF2FE8B7_66AC_46E4_A2C1_CB3E48AF9BA1

#include <iostream>
#include <memory>
#include <string>
#include <algorithm>
#include <type_traits>

#include "openssl/evp.h"
#include "openssl/bio.h"
#include "openssl/pem.h"


namespace cu
{


using EVP_PKEY_ref = std::shared_ptr<EVP_PKEY>;
class evp_pkey
{
public:
  inline evp_pkey();
  inline evp_pkey( EVP_PKEY_ref from );

  inline bool save_pubkey( const std::string &path ) const;
  inline bool save_prikey( const std::string &path, const std::string &pass = "" ) const;

  inline bool load_pubkey( const std::string &path );
  inline bool load_prikey( const std::string &path, const std::string &pass = "" );
  
  static inline evp_pkey (empty)();
  inline EVP_PKEY *get();

  inline void set_PKEY( std::shared_ptr<EVP_PKEY> from );
  inline void print() const;

private:
  EVP_PKEY_ref _body{nullptr};
};

struct EVP_PKEY_deleter
{
  inline void operator()(EVP_PKEY *pkey) const{
	EVP_PKEY_free(pkey);
  }
};


using rsa_EVP_PKEY_ref = std::shared_ptr<EVP_PKEY>;
inline rsa_EVP_PKEY_ref generate_rsa_EVP_PKEY_ref( int key_bits, int engine = NID_secp256k1 );
using ecdsa_EVP_PKEY_ref = std::shared_ptr<EVP_PKEY>;
inline ecdsa_EVP_PKEY_ref generate_ecdsa_EVP_PKEY_ref( int engine = NID_secp256k1 );

inline evp_pkey generate_rsa_evp_pkey( int key_bits, int engine = NID_secp256k1 );
inline evp_pkey generate_ecdsa_evp_pkey( int key_bits = 4096 );


inline evp_pkey::evp_pkey()
{
  return;
}

inline evp_pkey::evp_pkey( EVP_PKEY_ref from )
{
  _body = from;
}

inline bool evp_pkey::save_pubkey( const std::string &path ) const
{
  BIO *write_bio_fp = BIO_new_file( path.c_str() , "w" );
  if( write_bio_fp == nullptr ){
	return false;
  }

  if( PEM_write_bio_PUBKEY( write_bio_fp , _body.get() ) <= 0 ){
	BIO_vfree( write_bio_fp );
	return false;
  }

  BIO_vfree( write_bio_fp );
  return true;
}

inline bool evp_pkey::save_prikey( const std::string &path, const std::string &pass ) const
{
  BIO* write_bio_fp = BIO_new_file( path.c_str() ,"w" );
  if( write_bio_fp == nullptr ){
	return false;
  }

  // Fixed: Condition was inverted, and migrated from 3DES to AES-256-CBC
  if( pass.size() > 0 )
	PEM_write_bio_PKCS8PrivateKey( write_bio_fp , _body.get() , EVP_aes_256_cbc(), pass.c_str() , pass.size() , nullptr , nullptr );
  else
	PEM_write_bio_PKCS8PrivateKey( write_bio_fp , _body.get() , nullptr, nullptr, 0 , nullptr , nullptr );

  BIO_vfree( write_bio_fp );
  return true;
}

inline bool evp_pkey::load_pubkey( const std::string &path )
{
  BIO *read_bio_fp = BIO_new_file( path.c_str() ,"r");
  if( read_bio_fp == nullptr ){
	return false;
  }

  _body = std::shared_ptr<EVP_PKEY>( PEM_read_bio_PUBKEY( read_bio_fp , nullptr, nullptr, nullptr ) , EVP_PKEY_deleter() );

  BIO_vfree( read_bio_fp );
  return true;
}

inline bool evp_pkey::load_prikey( const std::string &path, const std::string &pass )
{
  BIO *read_bio_fp = BIO_new_file( path.c_str() ,"r");
  if( read_bio_fp == nullptr ){
	return false;
  }

  // Fixed: Condition was inverted
  if( pass.size() > 0 )
	_body = std::shared_ptr<EVP_PKEY>( PEM_read_bio_PrivateKey( read_bio_fp , nullptr, nullptr, const_cast<char*>(pass.c_str()) ), EVP_PKEY_deleter() );
  else
	_body = std::shared_ptr<EVP_PKEY>( PEM_read_bio_PrivateKey( read_bio_fp , nullptr, nullptr, nullptr ) , EVP_PKEY_deleter() );

  BIO_vfree( read_bio_fp );
  return true;
}

inline EVP_PKEY* evp_pkey::get()
{
  return _body.get();
}

evp_pkey inline evp_pkey::empty()
{
  evp_pkey ret;
  return ret;
}

inline void evp_pkey::set_PKEY( std::shared_ptr<EVP_PKEY> from )
{
  _body = from;
}

inline void evp_pkey::print() const
{
  if( _body == nullptr ){
	std::cout << "Key not set" << "\n";
	return;
  }

  BIO *output_bio = BIO_new_fp( stdout , 0 );
  EVP_PKEY_print_private( output_bio , _body.get() ,  0 , NULL ); std::cout << "\n\n";
  EVP_PKEY_print_public( output_bio, _body.get(),  0, NULL); std::cout << "\n";

  BIO_vfree( output_bio );
}


inline rsa_EVP_PKEY_ref generate_rsa_EVP_PKEY_ref( int key_bits, int engine )
{
  EVP_PKEY *PKEY = nullptr;
  EVP_PKEY_CTX *pctx;

  if( (PKEY = EVP_PKEY_new()) == nullptr ) return nullptr;

  if( (pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_RSA, NULL )) == nullptr ){
	EVP_PKEY_CTX_free( pctx );
	return nullptr;
  }

  if( EVP_PKEY_keygen_init( pctx ) <= 0 ){
	EVP_PKEY_CTX_free(pctx);
	return nullptr;
  }

  if( EVP_PKEY_CTX_set_rsa_keygen_bits( pctx, key_bits ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return nullptr;
  }

  if( EVP_PKEY_keygen( pctx , &PKEY ) <= 0 )
  {
	EVP_PKEY_CTX_free( pctx );
	return nullptr;
  }

  EVP_PKEY_CTX_free( pctx );
  return std::shared_ptr<EVP_PKEY>(PKEY, EVP_PKEY_deleter() );
}

inline evp_pkey generate_rsa_evp_pkey( int key_bits, int engine )
{
  evp_pkey ret = evp_pkey::empty();
  auto PKEY = generate_rsa_EVP_PKEY_ref(key_bits);
  ret.set_PKEY( PKEY );

  return ret;
}


};


#endif 
