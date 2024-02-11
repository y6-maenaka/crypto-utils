#include "../aes_manager.h"

namespace openssl_wrapper
{
namespace aes
{



bool case_1()
{
  std::cout << "HelloWorld" << "\n";
  
 
  size_t plainLength = 200;
  std::shared_ptr<unsigned char> plain = std::shared_ptr<unsigned char>( new unsigned char[plainLength] );
  memcpy( plain.get(), "HELLOWORLDhelloworld", plainLength );

  std::shared_ptr<unsigned char> ret;

  std::string pass = "0123456789123456";
  W_AESKey_128 key( pass );
 
  std::shared_ptr<unsigned char> cipherBin; size_t cipherBinLength;
  cipherBinLength = W_AES128Manager::encrypt( plain.get() , plainLength, &key , &cipherBin );

  std::cout << "cipherBinLength :: " << cipherBinLength << "\n";


  std::shared_ptr<unsigned char> decryptedBin; size_t decryptedBinLength = 0;
  cipherBinLength = W_AES128Manager::decrypt( cipherBin.get() , cipherBinLength , &key, &decryptedBin );

  std::cout << "復号後サイズ : " << cipherBinLength << "\n";


  std::cout << "-----------------------------------" << "\n";
  size_t temp_length = 10000;
  std::shared_ptr<unsigned char> temp_before = std::shared_ptr<unsigned char>( new unsigned char[temp_length] );

  size_t temp_after_length = 0;
  std::shared_ptr<unsigned char> temp_after;
  temp_after_length = W_AES128Manager::encrypt( temp_before.get(), temp_length, &key , &temp_after );
  std::cout << "10000 暗号化後 :: " << temp_after_length << "\n";


  std::cout << "===================================" << "\n";

  std::string plainFilePath = "sample.mp4";
  std::string cipherFilePath = "cipher.txt";
  W_AES128Manager::encryptStream( plainFilePath, 0 , 0 , &key , cipherFilePath );

  std::cout << "++++++++++++++++++++++++++++++++++++" << "\n";

    
  // std::string retFilePath = "_sample.mp4";
  // W_AES128Manager::decryptStream( cipherFilePath, 0 , 0, &key , retFilePath );




  std::cout << ".............................................." << "\n";
  std::string inputFilePath = "./generalmegabeast.txt";
  std::string outputFilePath = "./generalmegabeast.cipher";
  std::string retFilePath = "./_generalmegabeast.txt";

  for( int i=0; i<300; i++ )
  {
	std::cout << i << "\n";
	W_AES128Manager::encryptStream( inputFilePath , 0 , 0 , &key , outputFilePath );
	W_AES128Manager::decryptStream( outputFilePath , 0 , 0 , &key , retFilePath );
  }


  return false;
}



};
};
