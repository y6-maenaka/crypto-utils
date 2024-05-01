#include "../evp_pkey.hpp"


namespace cu
{


bool case_1()
{
  // std::shared_ptr<W_EVP_PKEY> wPkey = w_rsa_pkey();
  std::shared_ptr<w_evp_pkey> wPkey = w_empty_pkey();
  wPkey->loadPri( "./pri.pem" , "aaa" );
  // wPkey->loadPub( "./pri.pem" );

  wPkey->print();
  //wPkey->savePub( "./pub.pem" );
  //wPkey->savePri( "./pri.pem" , "Hello" );

  return false;
}


};
