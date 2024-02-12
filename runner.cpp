#include "runner.h"

#include "./w_evp_pkey/test/case_1.cpp"
#include "./w_rsa/test/case_1.cpp"
#include "./w_aes/test/case_1.cpp"
#include "./w_base64/base64.cpp"



int main()
{
  // openssl_wrapper::evp_pkey::case_1();
  // openssl_wrapper::rsa::case_1();
  // openssl_wrapper::aes::case_1();
  // openssl_wrapper::base64::case_1();
  
  std::shared_ptr<unsigned char> from = std::shared_ptr<unsigned char>( new unsigned char[5] );
  memcpy( from.get(), "hello", 5 );

  std::string encoded;
  encoded = openssl_wrapper::base64::W_Base64::encode( from.get(), 5 );

  for( int i=0; i<encoded.size(); i++ )
	std::cout << encoded.at(i);
  std::cout << "\n";

  std::cout << "エンコードサイズ :: " << encoded.size() << "\n";

  std::vector<unsigned char> decoded;
  decoded = openssl_wrapper::base64::W_Base64::decode( reinterpret_cast<const unsigned char*>(encoded.c_str()) , encoded.size() );
  for( int i=0; i<decoded.size(); i++ )
	printf("%c", decoded.at(i) );
  std::cout << "\n";

  std::cout << "でコードサイズ :: " << decoded.size() << "\n";


  std::cout << "\n\n" << "runner done" << "\n";
  return 0;
}
