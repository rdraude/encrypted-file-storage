cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)
project(EncryptedFileStorage)

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR} src)

# Add the executable
add_executable(encrypted-file-storage
    src/main.cpp
    src/encryption.cpp
    src/securefile.cpp
)

# Link OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(encrypted-file-storage OpenSSL::Crypto OpenSSL::SSL)
