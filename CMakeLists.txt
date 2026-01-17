cmake_minimum_required(VERSION 3.20)
project(crypto_utils VERSION 2.0.0 LANGUAGES CXX)

# C++20 required
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find OpenSSL 3.0+
find_package(OpenSSL 3.0 REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
else()
    message(FATAL_ERROR "OpenSSL 3.0+ is required")
endif()

# Header-only library
add_library(crypto_utils INTERFACE)
target_include_directories(crypto_utils INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(crypto_utils INTERFACE OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(crypto_utils INTERFACE cxx_std_20)

# Main executable (for testing/examples)
add_executable(main main.cpp)
target_link_libraries(main PRIVATE crypto_utils)

# Examples
option(BUILD_EXAMPLES "Build example programs" ON)
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Installation
install(TARGETS crypto_utils
    EXPORT crypto_utils-targets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/crypto_utils
    DESTINATION include
)

install(EXPORT crypto_utils-targets
    FILE crypto_utils-targets.cmake
    NAMESPACE crypto_utils::
    DESTINATION lib/cmake/crypto_utils
)

# Generate version file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/crypto_utils-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/crypto_utils-config-version.cmake"
    DESTINATION lib/cmake/crypto_utils
)
