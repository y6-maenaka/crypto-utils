cmake_minimum_required( VERSION 3.2 )

project( CRYPTO_UTILS CXX )

find_package( PkgConfig REQUIRED )


if(APPLE)
  find_package( OPENSSL REQUIRED )
elseif(UNIX)
  find_package( OpenSSL REQUIRED )
else()
  # winは未定義
endif()



if( OPENSSL_FOUND )
  include_directories( ${OPENSSL_INCLUDE_DIR} )
  message( STATUS "Using OpenSSL ${OPENSSL_VERSION}" )
  message( STATUS "Openssl IncludeDir :: ${OPENSSL_INCLUDE_DIR}" )
else()
  message("(Failure) Found OPENSSL")
endif()


add_executable( main main.cpp )
target_link_libraries( main PRIVATE
	${OPENSSL_LIBRARIES}
)

# add_definitions( -std=c++20 -w )
add_definitions( -std=c++20 )

