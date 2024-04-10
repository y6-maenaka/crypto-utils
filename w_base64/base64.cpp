#include "base64.h"


#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/buffer.h"



namespace openssl_wrapper
{
namespace base64
{


namespace {
  struct BIOFreeAll{ void operator()(BIO* p){ BIO_free_all(p);}};
}


std::string W_Base64::encode( const unsigned char* from , const std::size_t fromLength )
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

std::vector<unsigned char> W_Base64::decode( const unsigned char* from , const std::size_t fromLength )
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

// referenced from https://stackoverflow.com/questions/5288076/base64-encoding-and-decoding-with-openssl



};
};
