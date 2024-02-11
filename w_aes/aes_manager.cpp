#include "aes_manager.h"

#include "openssl/aes.h"
#include "openssl/err.h"

namespace openssl_wrapper
{
namespace aes
{



std::pair< size_t , std::shared_ptr<unsigned char> > W_AES128Manager::encrypt4096Base( const unsigned char* plainBin , EVP_CIPHER_CTX* cctx, size_t size )
{
  std::shared_ptr<unsigned char> cipherBin = std::shared_ptr<unsigned char>( new unsigned char[size + 16] );
  int cipherBinLength = 0;

  if( EVP_EncryptUpdate( cctx , cipherBin.get(), &cipherBinLength, plainBin, size ) <= 0 ){
	return std::make_pair( 0 , nullptr );
  }

  return std::make_pair( cipherBinLength, cipherBin );
}

std::pair< size_t , std::shared_ptr<unsigned char> > W_AES128Manager::decrypt4096Base( const unsigned char* cipherBin , EVP_CIPHER_CTX* cctx , size_t size )
{
  std::shared_ptr<unsigned char> plainBin = std::shared_ptr<unsigned char>( new unsigned char[size + 16] );
  // std::shared_ptr<unsigned char> plainBin = std::shared_ptr<unsigned char>( new unsigned char[size] );
  int plainBinLength = 0;

  if( EVP_DecryptUpdate( cctx , plainBin.get(), &plainBinLength , cipherBin, size ) <= 0 ){
	std::cout << plainBinLength << "\n";
	return std::make_pair( 0 , nullptr );
  }

  return std::make_pair( plainBinLength, plainBin );
}






size_t W_AES128Manager::encrypt( const unsigned char* plainBin , const size_t plainBinLength , W_AESKey_128* key ,std::shared_ptr<unsigned char> *cipherBin )
{
  EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();

  if( EVP_EncryptInit_ex( cctx , EVP_aes_128_cbc(), nullptr/* engine */ , key->raw() , nullptr /* 初期ベクトル*/ ) <= 0 )
  {
	EVP_CIPHER_CTX_free( cctx );
	return 0;
  }
   
  *cipherBin = std::shared_ptr<unsigned char>( new unsigned char[W_AES128Manager::encryptLength(plainBinLength)] );

  int unpaddedCipherLength = 0;
  if( EVP_EncryptUpdate( cctx , (*cipherBin).get() , &unpaddedCipherLength , plainBin, plainBinLength ) <= 0 )
  {
	EVP_CIPHER_CTX_free( cctx );
	return 0;
  }

  int paddedCipherLength = 0;
  if( EVP_EncryptFinal_ex( cctx , (*cipherBin).get() + unpaddedCipherLength, &paddedCipherLength ) <= 0 )
  {
	EVP_CIPHER_CTX_free( cctx );
	return 0;
  }

  return unpaddedCipherLength + paddedCipherLength;
}


size_t W_AES128Manager::encryptStream( std::string plainFilePath , size_t begin , size_t size , W_AESKey_128* key, std::string cipherFilePath )
{
  if( !(std::filesystem::exists(plainFilePath)) ) return 0;
  std::uintmax_t fileSize = std::filesystem::file_size(plainFilePath);

  struct PlainFile
  {
	std::ifstream stream;

	PlainFile( std::string filePath, unsigned int offset ){
	  stream.open(filePath.c_str(), std::ios::binary ); 
	  stream.seekg( offset , std::ios::beg ); // set begin ptr
	};
  } plainFile( plainFilePath , begin );

  struct CipherFile
  {
	std::ofstream stream;

	CipherFile( std::string filePath ){
	  stream.open( filePath.c_str(), std::ios::binary ); 
	  stream.seekp( 0 , std::ios::beg );
	};
  } cipherFile( cipherFilePath );


  EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
  if( EVP_EncryptInit_ex( cctx , EVP_aes_128_cbc(), nullptr , key->raw() , nullptr ) <= 0 )
  {
	EVP_CIPHER_CTX_free( cctx );
	return 0;
  }
  
  if( size == 0 ) size = fileSize;
  size_t plainDataLength = 0;
  plainDataLength = ( (begin + size) > fileSize ) ? fileSize - begin : size; // ファイルサイズを超えたら打ち切る

  size_t fixedUpdateCount = floor( plainDataLength / 4096 );
  size_t remainDataLength = plainDataLength - (fixedUpdateCount * 4096);

  int encryptedTotalLength = 0;
  std::pair< size_t, std::shared_ptr<unsigned char> > encrypted;
  std::shared_ptr<char> readedData = std::shared_ptr<char>( new char[4096] );
  for( int i=0; i < fixedUpdateCount; i++ )
  {
	plainFile.stream.read( readedData.get(), 4096 );
	encrypted = W_AES128Manager::encrypt4096Base( reinterpret_cast<unsigned char*>(readedData.get()), cctx );
	if( encrypted.first <= 0 ){
	  EVP_CIPHER_CTX_free( cctx );
	  return 0;
	}
	encryptedTotalLength += encrypted.first;
	cipherFile.stream.write( reinterpret_cast<const char*>(encrypted.second.get()) , encrypted.first );
  }
  
  int finalLength = 0;
  plainFile.stream.read( readedData.get(), remainDataLength );
  encrypted = W_AES128Manager::encrypt4096Base( reinterpret_cast<unsigned char*>(readedData.get()), cctx , remainDataLength );
  if( encrypted.first <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return 0;
  }

  if( EVP_EncryptFinal_ex( cctx , (encrypted.second).get() + encrypted.first , &finalLength ) <= 0 )
  {
	EVP_CIPHER_CTX_free( cctx );
	return 0;
  }

  encryptedTotalLength += encrypted.first + finalLength;
  cipherFile.stream.write( reinterpret_cast<const char*>(encrypted.second.get()), encrypted.first + finalLength );

  return encryptedTotalLength;
}


size_t W_AES128Manager::decrypt( const unsigned char* cipherBin, const size_t cipherLength, W_AESKey_128*key , std::shared_ptr<unsigned char> *plainBin )
{
  EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();

  if( EVP_DecryptInit_ex( cctx , EVP_aes_128_cbc(), nullptr/* engine */ , key->raw() , nullptr /* 初期ベクトル*/ ) <= 0 )
  {
	EVP_CIPHER_CTX_free( cctx );
	return 0;
  }

  *plainBin = std::shared_ptr<unsigned char>( new unsigned char[cipherLength] );

  int unpaddedLength = 0;
  if( EVP_DecryptUpdate( cctx , (*plainBin).get(), &unpaddedLength, cipherBin, cipherLength ) <= 0 )
  {
	EVP_CIPHER_CTX_free( cctx );
	return 0;
  }

  int paddedCipherLength = 0;
  if( EVP_DecryptFinal( cctx , (*plainBin).get() + unpaddedLength ,  &paddedCipherLength ) <= 0 )
  {
	EVP_CIPHER_CTX_free( cctx );
	return 0;
  }

  return unpaddedLength + paddedCipherLength;
}


size_t W_AES128Manager::decryptStream( std::string cipherFilePath, size_t begin , size_t size , W_AESKey_128* key , std::string plainFilePath )
{ 
  if( !(std::filesystem::exists(cipherFilePath)) ) return 0;
  std::uintmax_t fileSize = std::filesystem::file_size(cipherFilePath);

   struct CipherFile
   {
	std::ifstream stream;
	CipherFile( std::string filePath , unsigned int offset ){
	  stream.open( filePath.c_str(), std::ios::binary ); 
	  stream.seekg( offset , std::ios::beg );
	};
  } cipherFile( cipherFilePath , begin );

  struct PlainFile
  {
	std::ofstream stream;
	PlainFile( std::string filePath ){
	  stream.open(filePath.c_str(), std::ios::binary ); 
	  stream.seekp( 0, std::ios::beg );
	};
  } plainFile( plainFilePath ); 

  EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
  if( EVP_DecryptInit_ex( cctx , EVP_aes_128_cbc(), nullptr , key->raw() , nullptr ) <= 0 )
  {
	EVP_CIPHER_CTX_free( cctx ); 
	return 0;
  }

  if( size == 0 ) size = fileSize;
  size_t cipherDataLength = 0;
  cipherDataLength = ( (begin + size) > fileSize ) ? fileSize - begin : size;
  if( (cipherDataLength % 16) != 0 ) return 0; // 対象が正常に暗号化されていない可能性がある

  int decryptedTotalLength = 0;
  int updateCount = floor(cipherDataLength / 4096);
  size_t remainDataLength = cipherDataLength - (updateCount * 4096);

  std::shared_ptr<char> readedData = std::shared_ptr<char>( new char[4096] );
  std::pair< size_t , std::shared_ptr<unsigned char> > decrypted;
  for( int i=0; i<updateCount; i++ )
  {
	cipherFile.stream.read( readedData.get(), 4096 );
	decrypted = W_AES128Manager::decrypt4096Base( reinterpret_cast<unsigned char*>(readedData.get()) , cctx );
	if( decrypted.first <= 0 ){
	  EVP_CIPHER_CTX_free( cctx );
	  return 0;
	}
	decryptedTotalLength += decrypted.first;
	plainFile.stream.write( reinterpret_cast<const char*>(decrypted.second.get()), decrypted.first );
  }
  
  int finalLength = 0;
  cipherFile.stream.read( readedData.get(), remainDataLength );
  decrypted = W_AES128Manager::decrypt4096Base( reinterpret_cast<unsigned char*>(readedData.get()), cctx , remainDataLength );
  if( decrypted.first <= 0 ){
	EVP_CIPHER_CTX_free( cctx );
	return 0;
  }

  int flag = 0;
  if( (flag = EVP_DecryptFinal_ex( cctx , (decrypted.second).get() + decrypted.first , &finalLength )) <= 0 )
  {
	EVP_CIPHER_CTX_free( cctx ); 
	return 0;
  }

  decryptedTotalLength += decrypted.first + finalLength;
  plainFile.stream.write( reinterpret_cast<const char*>( decrypted.second.get()) , decrypted.first + finalLength );

  return decryptedTotalLength;
}







size_t W_AES128Manager::encryptLength( size_t plainBinLength )
{
  size_t unpaddedLength = floor( plainBinLength / AES_CBC_128_BYTES  ) * AES_CBC_128_BYTES ;
  return unpaddedLength + AES_CBC_128_BYTES ;
}






};
};
