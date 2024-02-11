#include "runner.h"

#include "./w_evp_pkey/test/case_1.cpp"
#include "./w_rsa/test/case_1.cpp"
#include "./w_aes/test/case_1.cpp"



int main()
{
  // openssl_wrapper::evp_pkey::case_1();
  // openssl_wrapper::rsa::case_1();
  openssl_wrapper::aes::case_1();
  



  std::cout << "\n\n" << "runner done" << "\n";
  return 0;
}
