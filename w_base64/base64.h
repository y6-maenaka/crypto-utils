#ifndef C9E589D5_A6E7_42C7_9927_5DF6E261BED1
#define C9E589D5_A6E7_42C7_9927_5DF6E261BED1


#include <iostream>
#include <memory>
#include <string>
#include <vector>




namespace openssl_wrapper
{
namespace base64
{



class W_Base64
{
public:
  static std::string encode( const unsigned char* from , const size_t fromLength );
  static std::vector<unsigned char> decode( const unsigned char* from , const size_t fromLength );
};



};
};


#endif 


