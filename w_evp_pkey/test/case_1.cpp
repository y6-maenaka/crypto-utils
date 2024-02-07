#include "../evp_pkey.h"


namespace openssl_wrapper
{
namespace evp_pkey
{








bool case_1()
{
  // std::shared_ptr<W_EVP_PKEY> wPkey = w_rsa_pkey();
  std::shared_ptr<W_EVP_PKEY> wPkey = w_empty_pkey();
  wPkey->loadPri( "./pri.pem" , "aaa" );
  // wPkey->loadPub( "./pri.pem" );

  wPkey->print();
  //wPkey->savePub( "./pub.pem" );
  //wPkey->savePri( "./pri.pem" , "Hello" );

  return false;
}









};
};
