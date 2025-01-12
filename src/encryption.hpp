#pragma once

#include <vector>
#include <string>
#include <random>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <iomanip>

// Generate a random key for AES encryption
void generateKey(size_t length, std::string& key); //default length is 16 bytes

// Convert binary data to a hex string
void toHex(const std::vector<unsigned char>& data, std::string& hexString);

// Convert a hex string back to binary data
void fromHex(const std::string& hex, std::vector<unsigned char>& result);

// Function to encrypt plaintext using AES
std::vector<unsigned char> encryptAES(const std::vector<unsigned char>& plaintext, const std::string& key);

// Function to decrypt ciphertext using AES
std::vector<unsigned char> decryptAES(const std::vector<unsigned char>& ciphertext, const std::string& key);