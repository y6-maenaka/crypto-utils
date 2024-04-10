#ifndef AF2FE8B7_66AC_46E4_A2C1_CB3E48AF9BA1
#define AF2FE8B7_66AC_46E4_A2C1_CB3E48AF9BA1

#include <iostream>
#include <memory>
#include <string>

#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/bio.h"
#include "openssl/pem.h"


namespace openssl_wrapper
{
namespace evp_pkey
{



class W_EVP_PKEY
{
private:
  std::shared_ptr<EVP_PKEY> _body = nullptr;

  int _status;
  std::string _keyType;

public:
  void pkey( std::shared_ptr<EVP_PKEY> fromPkey );
  
  W_EVP_PKEY();
  W_EVP_PKEY( std::string pemPath );
  W_EVP_PKEY( std::shared_ptr<EVP_PKEY> fromPkey );

  bool savePub( std::string path );
  bool savePri( std::string path, std::string pass );

  bool loadPub( std::string path );
  bool loadPri( std::string path, std::string pass );

  std::shared_ptr<EVP_PKEY> pkey();
  EVP_PKEY* rawPkey();

  int type();
  void print() const;
};


struct EVP_PKEY_deleter
{
  void operator ()(EVP_PKEY* key) const {
	EVP_PKEY_free(key);
  }
};


std::shared_ptr<EVP_PKEY> empty_pkey();
std::shared_ptr<EVP_PKEY> rsa_pkey( int keyBits , int engine = NID_undef );
std::shared_ptr<EVP_PKEY> ecdsa_pkey( int engine = NID_secp256k1 );


std::shared_ptr<W_EVP_PKEY> w_pkey( std::string pemPath );
std::shared_ptr<W_EVP_PKEY> w_empty_pkey();
std::shared_ptr<W_EVP_PKEY> w_rsa_pkey( int keyBits = 4096 );






};
};

#endif 
