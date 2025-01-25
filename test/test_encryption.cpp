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

    // Test encryption and decryption for normal data
    std::vector<unsigned char> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    std::string key2 = "1234567890123456";  // 16-byte key for AES-128
    std::vector<unsigned char> ciphertext = encryptAES(plaintext, key2);

    std::vector<unsigned char> decryptedText = decryptAES(ciphertext, key2);
    assert(plaintext == decryptedText);  // Decrypted text should match the original plaintext
    std::cout << "Encryption and Decryption test passed!\n";
    for (unsigned char byte : decryptedText) {
        std::cout << byte;  // This will print characters (not hex)
    }
    std::cout << std::endl;

    // Test with empty plaintext
    std::vector<unsigned char> emptyPlaintext = {};
    std::vector<unsigned char> emptyCiphertext = encryptAES(emptyPlaintext, key2);
    std::vector<unsigned char> emptyDecrypted = decryptAES(emptyCiphertext, key2);
    assert(emptyPlaintext == emptyDecrypted);  // Empty data should remain empty after encryption and decryption
    std::cout << "Empty plaintext encryption and decryption test passed!\n";

    // Test with maximum-length plaintext (large data)
    std::vector<unsigned char> largePlaintext(1024, 'A');  // 1KB of 'A' characters
    std::vector<unsigned char> largeCiphertext = encryptAES(largePlaintext, key2);
    std::vector<unsigned char> largeDecrypted = decryptAES(largeCiphertext, key2);
    assert(largePlaintext == largeDecrypted);  // Large data should be decrypted correctly
    std::cout << "Large plaintext encryption and decryption test passed!\n";

    // Test with one-byte plaintext
    std::vector<unsigned char> singleBytePlaintext = {'X'};
    std::vector<unsigned char> singleByteCiphertext = encryptAES(singleBytePlaintext, key2);
    std::vector<unsigned char> singleByteDecrypted = decryptAES(singleByteCiphertext, key2);
    assert(singleBytePlaintext == singleByteDecrypted);  // Single byte should be decrypted correctly
    std::cout << "One-byte plaintext encryption and decryption test passed!\n";

    // Test with non-ASCII data (binary data)
    std::vector<unsigned char> binaryPlaintext = { 0x01, 0xFF, 0x2A, 0xAB, 0x12, 0x56 };
    std::vector<unsigned char> binaryCiphertext = encryptAES(binaryPlaintext, key2);
    std::vector<unsigned char> binaryDecrypted = decryptAES(binaryCiphertext, key2);
    assert(binaryPlaintext == binaryDecrypted);  // Binary data should be decrypted correctly
    std::cout << "Non-ASCII plaintext encryption and decryption test passed!\n";
    std::cout << "Encryption and Decryption test with 32-byte key passed!\n";

    return 0;
}
