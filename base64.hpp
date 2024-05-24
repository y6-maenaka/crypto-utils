#ifndef C9E589D5_A6E7_42C7_9927_5DF6E261BED1
#define C9E589D5_A6E7_42C7_9927_5DF6E261BED1


#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/buffer.h"


namespace cu
{


class base64
{
public:
  static inline std::string encode( const unsigned char* from , const std::size_t fromLength );
  static inline std::vector<unsigned char> decode( const unsigned char* from , const std::size_t fromLength );
};


namespace {
  struct BIOFreeAll{ void operator()(BIO* p){ BIO_free_all(p);}};
}


std::string base64::encode( const unsigned char* from , const std::size_t fromLength )
{

  std::unique_ptr<BIO, BIOFreeAll > b64(BIO_new(BIO_f_base64()));
  BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL );  // 改行しない
  
  BIO* bio = BIO_new(BIO_s_mem()); // メモリバイオのセットアップ
  BIO_push( b64.get(), bio ); // encoderとメモリの結合

  BIO_write( b64.get(), from , fromLength ); // エンコーダに書き込み
  BIO_flush( b64.get() ); // 結果の書き出し ( おそらく連結したbioに書き出している )
  
  const char* encoded; std::size_t encodedLength;
  encodedLength = BIO_get_mem_data( bio , &encoded );
  std::string ret( encoded, encodedLength );

  return ret;
}

std::vector<unsigned char> base64::decode( const unsigned char* from , const std::size_t fromLength )
{
  std::unique_ptr<BIO, BIOFreeAll > b64(BIO_new(BIO_f_base64())); // デコーダの作成
  BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL ); // 改行しない

  BIO* source = BIO_new_mem_buf( from , -1 );
  BIO_push( b64.get(), source ); // 結合
  
  const int maxLen = fromLength / 4 * 3 + 1;
  std::vector<unsigned char> ret(maxLen);
  const int len = BIO_read( b64.get(), ret.data(), maxLen );
  ret.resize(len);

  return ret;
}


};


#endif 


