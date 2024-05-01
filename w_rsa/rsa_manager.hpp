#ifndef F71D9744_2F6F_4A69_A671_C924DAC6E5CE
#define F71D9744_2F6F_4A69_A671_C924DAC6E5CE

#include <iostream>
#include <memory>

#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/engine.h"


namespace cu
{


class w_evp_pkey;


class w_rsa_manager
{
public:
  static std::size_t encrypt( w_evp_pkey* wpkey , const unsigned char* plainBin , const std::size_t plainBinLength ,std::shared_ptr<unsigned char> *cipherBin );
  static std::size_t sign( w_evp_pkey* wpkey , const unsigned char* plainBin , const std::size_t plainBinLength ,std::shared_ptr<unsigned char> *signBin );

  static std::size_t decrypt( w_evp_pkey* wpkey , const unsigned char* cipherBin , const std::size_t cipherBinLength ,std::shared_ptr<unsigned char> *plainBin );
  static bool verify( w_evp_pkey* wpkey , const unsigned char* signBin , const std::size_t signBinLength , const unsigned char* msgBin /* ハッシュ前の本体バイナリ */ , const std::size_t msgBinLength );

  // void decrypt( evp_pkey::W_EVP_PKEY );
};


};


#endif 
