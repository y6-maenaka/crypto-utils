#ifndef B3A83E69_25B8_441B_8709_2255DEDAF37B
#define B3A83E69_25B8_441B_8709_2255DEDAF37B


#include <vector>
#include <algorithm>
#include <type_traits>


namespace cu
{


struct data_block
{
public:
  typedef std::byte elem_type;
  std::vector<elem_type> body;
  data_block();

  static inline data_block (empty)();
  inline std::string to_string() const;
  template < typename T > inline std::vector<T> to_vector() const;

  inline std::vector<std::byte> operator()();
  inline bool operator ==( const data_block &db ) const;
};


data_block::data_block()
{
  return;
}

inline std::string data_block::to_string() const
{
  std::string ret;
  std::transform( body.begin(), body.end(), ret.begin(), [](const std::byte &b){
	return static_cast<char>(std::to_integer<int>(b));
  });

  return ret;
}

template < typename T > inline std::vector<T> data_block::to_vector() const
{
  std::vector<T> ret;
  ret.reserve( body.size() );

  std::transform( body.begin(), body.end(), std::back_inserter(ret), [](const std::byte &b){
	return static_cast<T>(std::to_integer<int>(b));
	  });

  return ret;
}

inline data_block data_block::empty()
{
  data_block ret;
  return ret;
}

inline std::vector<std::byte> data_block::operator()()
{
  return body;
}

bool data_block::operator ==( const data_block &db ) const
{
  return std::equal( db.body.cbegin(), db.body.cend(), body.cbegin() );
}


};


#endif 
