#ifndef F71D9744_2F6F_4A69_A671_C924DAC6E5CE
#define F71D9744_2F6F_4A69_A671_C924DAC6E5CE

#include <iostream>
#include <memory>

#include "openssl/evp.h"
#include "openssl/rsa.h"
 #include "openssl/engine.h"



namespace openssl_wrapper
{
namespace evp_pkey
{
  class W_EVP_PKEY;
}


namespace rsa
{





class W_RSAManager
{
public:
  static size_t encrypt( evp_pkey::W_EVP_PKEY* wpkey , unsigned char* from , size_t fromLength ,std::shared_ptr<unsigned char> *out );
  static int sign( evp_pkey::W_EVP_PKEY* wpkey , unsigned char* plainText , size_t plainTextLength ,std::shared_ptr<unsigned char> md , size_t mdLength ); 

  static size_t decrypt( evp_pkey::W_EVP_PKEY* wpkey , unsigned char* from , size_t fromLength ,std::shared_ptr<unsigned char> *out );
  static bool verify( evp_pkey::W_EVP_PKEY* wpkey , unsigned char* plainText , size_t plainTextLength ,std::shared_ptr<unsigned char> md , size_t mdLength ); 

  // void decrypt( evp_pkey::W_EVP_PKEY );
};






};
};




#endif 
