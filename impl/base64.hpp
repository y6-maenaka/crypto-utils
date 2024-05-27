#ifndef C9E589D5_A6E7_42C7_9927_5DF6E261BED1
#define C9E589D5_A6E7_42C7_9927_5DF6E261BED1


#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <algorithm>
#include <type_traits>

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/buffer.h"
#include "./common.hpp"


namespace cu
{


/* template< typename Container > constexpr bool is_allowed_input_container() { // 指定した鍵の作成元が許可されているデータタイプか?
  return (
	std::is_same_v< Container, std::vector<std::byte>> 
	|| std::is_same_v< Container, std::vector<std::uint8_t> >
	|| std::is_same_v< Container, std::string> 
  );
} */

class base64
{
public:
  template < typename Container > static inline cu_result encode( const Container &input );
  template < typename Container > static inline cu_result decode( const Container &input );
};

namespace {
  struct BIOFreeAll{ void operator()(BIO* p){ BIO_free_all(p);}};
}


template < typename Container > inline cu_result base64::encode( const Container &input )
{
  // static_assert( is_allowed_input_container<Container>(), "Invaild input container type" );

  std::unique_ptr<BIO, BIOFreeAll > b64(BIO_new(BIO_f_base64()));
  BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL );  // 改行を挿入しない
 
  BIO* bio = BIO_new(BIO_s_mem()); // setup mem_bio
  BIO_push( b64.get(), bio ); // エンコーダとメモリを結合

  BIO_write( b64.get(), input.data() , input.size() ); // エンコーダに書き出し
  BIO_flush( b64.get() ); // 結果の書き出し ( おそらく連結したbioに書き出している )
 
  const char* ret_temp;
  std::size_t ret_len = BIO_get_mem_data( bio , &ret_temp );

  cu_result ret = cu_result::empty(); 
  (*ret).assign(reinterpret_cast<const cu_result::value_type*>(ret_temp), reinterpret_cast<const cu_result::value_type*>(ret_temp + ret_len));
  return ret;
}

template < typename Container > inline cu_result base64::decode( const Container &input )
{
  // static_assert( is_allowed_input_container<Container>(), "Invaild input container type" );

  std::unique_ptr<BIO, BIOFreeAll > b64(BIO_new(BIO_f_base64())); // デコーダの作成
  BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL ); // 改行しない

  BIO* source = BIO_new_mem_buf( input.data() , -1 );
  BIO_push( b64.get(), source ); // 結合
  
  const int max_len  = input.size() / 4 * 3 + 1;
  cu_result ret = cu_result::empty(); (*ret).resize( max_len );
  const int ret_len = BIO_read( b64.get(), (*ret).data(), max_len );
  (*ret).resize(ret_len);

  return ret;
}


};


#endif 


