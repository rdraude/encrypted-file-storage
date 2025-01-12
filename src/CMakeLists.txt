cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 11)
project(EncryptedFileStorage)

# Add the source files to create an executable
add_executable(encrypted-file-storage
    main.cpp
    encryption.cpp
    securefile.cpp
)

# Link OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(encrypted-file-storage OpenSSL::Crypto OpenSSL::SSL)
