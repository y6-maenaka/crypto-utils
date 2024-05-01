cmake_minimum_required( VERSION 3.2 )

project( OPENSSL_WRAPPER CXX )

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


add_library( W_BASE64 SHARED
			  ./w_base64/base64.cpp
)
target_link_libraries( W_BASE64 PUBLIC
						${OPENSSL_LIBRARIES}
)

add_library( W_SHA SHARED
			  ./w_sha/sha.cpp
)
target_link_libraries( W_SHA PUBLIC
						${OPENSSL_LIBRARIES}
)

add_library( W_EVP_PKEY SHARED
			  ./w_evp_pkey/evp_pkey.cpp
)
target_link_libraries( W_EVP_PKEY PUBLIC
						${OPENSSL_LIBRARIES}
)


add_library( W_RSA_MANAGER SHARED
			  ./w_rsa/rsa_manager.cpp
)
target_link_libraries( W_RSA_MANAGER PUBLIC
						W_EVP_PKEY
						W_SHA
						${OPENSSL_LIBRARIES}
)

add_library( W_AES_MANAGER SHARED
			  ./w_aes/aes_manager.cpp
)
target_link_libraries( W_AES_MANAGER PUBLIC
						${OPENSSL_LIBRARIES}
)



add_executable(runner runner.cpp)
target_link_libraries( runner PRIVATE 
						W_RSA_MANAGER
						W_AES_MANAGER
						W_EVP_PKEY
						W_BASE64
)


# add_definitions( -std=c++20 -w )
add_definitions( -std=c++20 )

