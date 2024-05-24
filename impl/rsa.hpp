#ifndef F71D9744_2F6F_4A69_A671_C924DAC6E5CE
#define F71D9744_2F6F_4A69_A671_C924DAC6E5CE

#include <iostream>
#include <memory>

#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/engine.h"

#include "./evp_pkey.hpp"
#include "./sha2.hpp"


namespace cu
{


class rsa
{
public:
  static inline std::vector<std::byte> encrypt();
};


};


#endif 
