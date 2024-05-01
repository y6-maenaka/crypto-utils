#include "runner.h"


int sha_test()
{
  const char* input_c = "HelloWorld";
  std::vector< std::uint8_t > input_v; 
  for( int i=0; i<std::strlen(input_c); i++ ) input_v.push_back(input_c[i]);
  // std::memcpy( input_v.data(), input_c, std::strlen(input_c)-1 );

  std::vector<std::uint8_t> ret = cu::w_sha::hash( input_v.data(), input_v.size(),cu::w_sha::hash_t::SHA1 );

  std::cout << "input_v size :: " << input_v.size() << "\n";
  std::cout << "md length :: " << ret.size() << "\n";
  for( int i=0; i<input_v.size(); i++ ) printf("%c", input_v[i] );
  std::cout << "\n";

  for( int i=0; i<ret.size(); i++ ) printf("%02X", ret[i] );
  std::cout << "\n";

  return 0;
}


int main()
{

  return sha_test();
  // openssl_wrapper::evp_pkey::case_1();
  // openssl_wrapper::rsa::case_1();
  // openssl_wrapper::aes::case_1();
  // openssl_wrapper::base64::case_1();
  
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
}
