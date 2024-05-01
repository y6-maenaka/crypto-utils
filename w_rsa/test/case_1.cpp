#include "../rsa_manager.hpp"


namespace cu
{


/* bool case_1()
{
  std::cout << __FILE__ << "\n";


  std::shared_ptr<w_evp_pkey> wpkey = w_rsa_pkey();
  //wpkey->print();


  std::shared_ptr<unsigned char> plain = std::shared_ptr<unsigned char>( new unsigned char[10] );
  memcpy( plain.get(), "HelloWorld", 10 );

  std::shared_ptr<unsigned char> encrypted;
  size_t encryptedLength = 0;
  encryptedLength = w_rsa_manager::encrypt( wpkey.get() ,plain.get() , 10 , &encrypted );
  std::cout << "encryptedLength :: " << encryptedLength << "\n";
  
  std::shared_ptr<unsigned char> signature;
  size_t signatureLength;
  signatureLength = w_rsa_manager::sign( wpkey.get(), plain.get(), 10 , &signature );


  std::cout << "Sign Lenght :: " << signatureLength  << "\n";
  memcpy( signature.get() + 10 , "aq", 2 );
  int verifyRet = w_rsa_manager::verify( wpkey.get(), signature.get() , signatureLength, plain.get() , 10 );
  std::cout << "署名結果 :: " << verifyRet << "\n";
  
  
  std::shared_ptr<unsigned char> decrypted;
  size_t decryptedLength = 0;
  decryptedLength = w_rsa_manager::decrypt( wpkey.get(), encrypted.get(), encryptedLength, &decrypted );
  std::cout << "decryptedLength :: " << decryptedLength << "\n";

  return true;
} */


};
