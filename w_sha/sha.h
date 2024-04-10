#ifndef C5D3220A_2E49_447F_974D_B8A0E140ED8E
#define C5D3220A_2E49_447F_974D_B8A0E140ED8E

#include <iostream>
#include <string>
#include <memory>

#include "openssl/evp.h"


namespace openssl_wrapper
{
namespace sha
{


class W_SHA
{
public:
  static std::size_t hash( const unsigned char* from , const std::size_t fromLength , std::shared_ptr<unsigned char> *out , std::string type );
};


};
};


#endif // 


