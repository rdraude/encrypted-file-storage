#include <iostream>
#include "encryption.hpp"

int main() {
    // Test generateKey function
    std::string key;
    size_t keyLength = 16; // AES key size (in bytes)
    generateKey(keyLength, key);

    std::cout << "Generated Key: " << key << std::endl;
    std::cout << "Key length: " << key.length() << " bytes" << std::endl;
    
    // Check if key length matches
    if (key.length() == keyLength) {
        std::cout << "Key length test passed!" << std::endl;
    } else {
        std::cout << "Key length test failed! Your key's length is " << key.length() << std::endl;
    }

    // Test toHex and fromHex functions
    std::vector<unsigned char> data = { 0x01, 0x2A, 0x7F, 0xBB };
    std::string hexStr; 
    toHex(data, hexStr);

    std::cout << "Hex String: " << hexStr << std::endl;

    // Convert the hex string back to binary
    std::vector<unsigned char> decodedData;
    fromHex(hexStr, decodedData);
    std::cout << "Decoded Data: ";
    for (unsigned char byte : decodedData) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;

    // Check if the data matches
    if (data == decodedData) {
        std::cout << "Hex conversion test passed!" << std::endl;
    } else {
        std::cout << "Hex conversion test failed!" << std::endl;
    }

    return 0;
}
