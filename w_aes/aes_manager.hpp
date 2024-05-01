#ifndef B9839E16_5691_47CB_B6D4_E8C6D20BF974
#define B9839E16_5691_47CB_B6D4_E8C6D20BF974


#include <iostream>
#include <fstream>
#include <string>
#include <array>
#include <memory>
#include <cmath>
#include <filesystem>
#include <cstring>

#include "openssl/evp.h"


namespace cu
{


constexpr std::size_t AES_CBC_128_BYTES = 16;


class W_AESKey_128
{
private:
  std::shared_ptr<unsigned char> _body;

public:
  W_AESKey_128( std::string fromStr ) : _body(nullptr)
  {
	if( fromStr.size() != AES_CBC_128_BYTES  ) return;
	_body = std::shared_ptr<unsigned char>( new unsigned char[AES_CBC_128_BYTES ] );
	memcpy( _body.get() , fromStr.c_str(), AES_CBC_128_BYTES  );
  };
  const unsigned char* raw() const{
	return _body.get();
  };
};

  
class W_AES128Manager
{
private:
  static std::pair< std::size_t , std::shared_ptr<unsigned char> > encrypt4096Base( const unsigned char* plainBin , EVP_CIPHER_CTX* cctx ,std::size_t size = 4096 );
  static std::pair< std::size_t , std::shared_ptr<unsigned char> > decrypt4096Base( const unsigned char* cipherBin , EVP_CIPHER_CTX* cctx , std::size_t size = 4096 );

public:
  static std::size_t encrypt( const unsigned char* plainBin , const std::size_t plainBinLength , W_AESKey_128* key ,std::shared_ptr<unsigned char> *cipherBin );
  static std::size_t encryptStream( std::string plainFilePath , std::size_t begin , std::size_t size , W_AESKey_128* key , std::string cipherFilePath );

  static std::size_t decrypt( const unsigned char* cipherBin, const std::size_t cipherLength, W_AESKey_128*key , std::shared_ptr<unsigned char> *plainBin );
  static std::size_t decryptStream( std::string cipherFilePath, std::size_t begin, std::size_t size , W_AESKey_128* key , std::string plainFilePath ); 

  static std::size_t encryptLength( std::size_t plainBinLength );
};


};


#endif 


