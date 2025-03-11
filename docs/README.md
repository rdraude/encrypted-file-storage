# Encrypted File Storage

A C++ command-line application for securely encrypting and decrypting `.txt` files using AES encryption with OpenSSL.

## Features
- Encrypts `.txt` files and stores them securely in an `encrypted/` directory.
- Decrypts encrypted files back to plaintext in a `decrypted/` directory.
- Uses AES encryption with OpenSSL for secure file handling.
- Command-line interface for simple usability.

## Installation

### Prerequisites
- C++ compiler (`g++` or `clang++`)
- CMake
- OpenSSL

### Build Instructions
```sh
git clone https://github.com/yourusername/encrypted-file-storage.git
cd encrypted-file-storage
mkdir build && cd build
cmake ..
make
