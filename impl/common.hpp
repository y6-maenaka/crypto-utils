#ifndef B3A83E69_25B8_441B_8709_2255DEDAF37B
#define B3A83E69_25B8_441B_8709_2255DEDAF37B


#include <vector>
#include <algorithm>
#include <type_traits>


namespace cu
{


struct cu_result
{
public:
  typedef std::byte elem_type;
  using value_type = elem_type;

  std::vector<elem_type> body;
  inline cu_result();

  static inline cu_result (empty)();
  inline std::string to_string() const;
  template < typename T > inline std::vector<T> to_vector() const;
  template < typename T, std::size_t N > std::array<T, N> to_array() const;

  inline bool is_invalid() const;
  inline std::vector<std::byte>& operator()();
  inline std::vector<std::byte>& operator *();
  inline bool operator ==( const cu_result &db ) const;
};


template < typename T > inline std::vector<std::byte> to_vector( const T *input, std::size_t input_size );


inline cu_result::cu_result()
{
  return;
}

inline std::string cu_result::to_string() const
{
  std::string ret;
  ret.resize( body.size() );

  std::transform( body.begin(), body.end(), ret.begin(), [](const cu_result::value_type &b){
	return static_cast<std::string::value_type>(std::to_integer<int>(b));
  });

  return ret;
}

template < typename T > inline std::vector<T> cu_result::to_vector() const
{
  std::vector<T> ret;

  std::transform( body.begin(), body.end(), std::back_inserter(ret), [](const cu_result::value_type &b){
	return static_cast<T>(std::to_integer<int>(b));
	  });

  return ret;
}

template < typename T, std::size_t N > inline std::array<T, N> cu_result::to_array() const
{
  std::array< T, N > ret;

  std::size_t copy_size = std::min( body.size(), N );
  std::transform( body.begin(), body.begin() + copy_size, ret.begin(), []( const cu_result::value_type &b ){
	return static_cast<T>(std::to_integer<int>(b));
	  });
  
  return ret;
}

inline cu_result cu_result::empty()
{
  cu_result ret;
  return ret;
}

inline bool cu_result::is_invalid() const
{
  return (*this) == cu_result::empty();
}

inline std::vector<std::byte>& cu_result::operator()()
{
  return body;
}

inline std::vector<std::byte>& cu_result::operator *()
{
  return body;
}

inline bool cu_result::operator ==( const cu_result &db ) const
{
  if( db.body.size() != body.size() ) return false;
  return std::equal( body.cbegin(), body.cend(), db.body.cbegin() );
  // return std::equal( db.body.cbegin(), db.body.cend(), body.cbegin() );
}


template < typename T > inline std::vector<std::byte> to_vector( const T *input, std::size_t input_size )
{
  std::vector<std::byte> ret;
  ret.reserve( input_size );

  std::transform( input, input + input_size, std::back_inserter(ret), [](const T &value ){
	return static_cast<std::byte>(value);
  });

  return ret;
}


};


#endif 
