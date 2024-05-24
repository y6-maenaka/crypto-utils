#include <iostream>
#include <vector>

// #include "./base64.hpp"
// #include "./sha.hpp"
// #include "./evp_pkey.hpp"
#include "./crypto_utils.hpp"
// #include "./rsa.hpp"

#include "./test/setup_aes.cpp"
#include "./test/setup_base64.cpp"
#include "./test/setup_sha.cpp"


int main()
{

  return setup_sha();
  return setup_aes();
  return setup_base64();



  // openssl_wrapper::evp_pkey::case_1();
  // openssl_wrapper::rsa::case_1();
  // openssl_wrapper::aes::case_1();
  // openssl_wrapper::base64::case_1();
 
  /*
  std::shared_ptr<unsigned char> from = std::shared_ptr<unsigned char>( new unsigned char[5] );
  memcpy( from.get(), "hello", 5 );

  std::string encoded;
  encoded = cu::w_base64::encode( from.get(), 5 );

  for( int i=0; i<encoded.size(); i++ )
	std::cout << encoded.at(i);
  std::cout << "\n";

  std::cout << "エンコードサイズ :: " << encoded.size() << "\n";

  std::vector<unsigned char> decoded;
  decoded = cu::w_base64::decode( reinterpret_cast<const unsigned char*>(encoded.c_str()) , encoded.size() );
  for( int i=0; i<decoded.size(); i++ )
	printf("%c", decoded.at(i) );
  std::cout << "\n";

  std::cout << "でコードサイズ :: " << decoded.size() << "\n";


  std::cout << "\n\n" << "runner done" << "\n";
  return 0;
  */
}
