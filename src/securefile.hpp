#include <fstream>
#include <vector>
#include <iostream>

// Function to encrypt a file
// Parameters:
// - inputPath: Path to the input file to be encrypted
// - outputPath: Path to the output file where the encrypted data will be saved
// - key: Encryption key to be used
bool encryptFile(const std::string& inputPath, const std::string& key);

// Function to decrypt a file
// Parameters:
// - inputPath: Path to the input file to be decrypted
// - outputPath: Path to the output file where the decrypted data will be saved
// - key: Decryption key to be used
bool decryptFile(const std::string& inputPath, const std::string& key);
