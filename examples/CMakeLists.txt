# Example programs demonstrating crypto_utils v2.0

# Hash examples
add_executable(example_hash hash_example.cpp)
target_link_libraries(example_hash PRIVATE crypto_utils)

# Cipher examples
add_executable(example_cipher cipher_example.cpp)
target_link_libraries(example_cipher PRIVATE crypto_utils)

# Asymmetric crypto examples
add_executable(example_asymmetric asymmetric_example.cpp)
target_link_libraries(example_asymmetric PRIVATE crypto_utils)

# Encoding examples
add_executable(example_encoding encoding_example.cpp)
target_link_libraries(example_encoding PRIVATE crypto_utils)

# Full workflow example
add_executable(example_full_workflow full_workflow_example.cpp)
target_link_libraries(example_full_workflow PRIVATE crypto_utils)
