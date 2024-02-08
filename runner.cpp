#include "runner.h"

#include "./w_evp_pkey/test/case_1.cpp"
#include "./w_rsa/test/case_1.cpp"



int main()
{

  std::cout << "Hello World" << "\n";

  // openssl_wrapper::evp_pkey::case_1();
  openssl_wrapper::rsa::case_1();

  return 0;
}
