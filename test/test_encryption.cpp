#include <iostream>
#include "../src/encryption.hpp"
#include <cassert>

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

    // Test encryption (simple example, will do more when decrypt is implemented)
    std::vector<unsigned char> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    std::string key2 = "1234567890123456";  // 16-byte key for AES-128
    std::vector<unsigned char> ciphertext = encryptAES(plaintext, key2);

    // The ciphertext should include the IV, so the length will be the plaintext size + 16 for the IV
    assert(!ciphertext.empty());  // Ciphertext should not be empty
    std::cout << "Encryption Completed. Ciphertext length: " << ciphertext.size() << " bytes.\n";

    int count = 0;
    for (unsigned char byte : ciphertext) {
        count++;
    }

    std::cout << "Counted ciphertext elements: " << std::dec << count << std::endl;

    // Test to ensure the IV has 16 elements
    assert(count == 32);
    std::cout << "Test passed: ciphertext has 32 elements.\n";

    return 0;
}
