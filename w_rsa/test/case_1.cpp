#include "../rsa_manager.h"


namespace openssl_wrapper
{
namespace rsa
{




bool case_1()
{
  std::cout << __FILE__ << "\n";


  std::shared_ptr<evp_pkey::W_EVP_PKEY> wpkey = evp_pkey::w_rsa_pkey();
  //wpkey->print();


  std::shared_ptr<unsigned char> plain = std::shared_ptr<unsigned char>( new unsigned char[10] );
  memcpy( plain.get(), "HelloWorld", 10 );

  std::shared_ptr<unsigned char> encrypted;
  size_t encryptedLength = 0;
  encryptedLength = W_RSAManager::encrypt( wpkey.get() ,plain.get() , 10 , &encrypted );
  std::cout << "encryptedLength :: " << encryptedLength << "\n";
  
  std::shared_ptr<unsigned char> signature;
  size_t signatureLength;
  signatureLength = W_RSAManager::sign( wpkey.get(), plain.get(), 10 , &signature );


  std::cout << "Sign Lenght :: " << signatureLength  << "\n";

  
  std::shared_ptr<unsigned char> decrypted;
  size_t decryptedLength = 0;
  decryptedLength = W_RSAManager::decrypt( wpkey.get(), encrypted.get(), encryptedLength, &decrypted );
  std::cout << "decryptedLength :: " << decryptedLength << "\n";

  return true;
}




};
};
