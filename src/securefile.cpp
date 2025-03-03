#include "securefile.hpp"
#include "encryption.hpp"

bool encryptFile(const std::string& inputFilename, const std::string& key) {
    std::ifstream inputFile(inputFilename, std::ios::binary);
    if (!inputFile) {
        throw std::runtime_error("Error: Could not open input file for reading.");
    }

    std::filesystem::path encryptedDir = "./encrypted";

    // Ensure directory exists
    if (!std::filesystem::exists(encryptedDir)) {
        std::filesystem::create_directory(encryptedDir);
    }

    // Get absolute path of directory
    std::filesystem::path encryptedPath = std::filesystem::canonical(encryptedDir);

    // Extract only the filename (prevent relative path issues)
    std::filesystem::path filenameOnly = std::filesystem::path(inputFilename).filename();

    // Append filename to directory path
    std::filesystem::path filePath = encryptedPath / filenameOnly;

    std::cout << "Attempting to write encrypted file to: " << filePath.string() << std::endl;

    // Open the file
    std::ofstream encryptedFile(filePath, std::ios::binary);
    if (!encryptedFile) {
        throw std::runtime_error("Error: Could not create encrypted file.");
    }

    // Read entire file into a vector
    std::vector<unsigned char> plaintext((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    
    // Encrypt the data
    std::vector<unsigned char> ciphertext = encryptAES(plaintext, key);

    // Convert to hex and write to file
    std::string hexCiphertext;
    toHex(ciphertext, hexCiphertext);
    encryptedFile << hexCiphertext;

    std::cout << "Encryption completed. File saved as: " << filePath.string() << std::endl;
    return true;
}

bool decryptFile(const std::string& inputFilename, const std::string& key) {
    std::ifstream inputFile(inputFilename, std::ios::binary);
    if (!inputFile) {
        throw std::runtime_error("Error: Could not open encrypted file for reading.");
    }

    std::filesystem::path decryptedDir = "./decrypted";  // FIXED: Use correct directory

    // Ensure directory exists
    if (!std::filesystem::exists(decryptedDir)) {
        std::filesystem::create_directory(decryptedDir);
    }

    // Get absolute path of directory
    std::filesystem::path decryptedPath = std::filesystem::canonical(decryptedDir);

    // Extract only the filename (prevent relative path issues)
    std::filesystem::path filenameOnly = std::filesystem::path(inputFilename).filename();

    // Append filename to directory path
    std::filesystem::path filePath = decryptedPath / filenameOnly;

    std::cout << "Attempting to write decrypted file to: " << filePath.string() << std::endl;

    // Open the file
    std::ofstream decryptedFile(filePath, std::ios::binary);
    if (!decryptedFile) {
        throw std::runtime_error("Error: Could not create decrypted file.");
    }

    // Read the hex-encoded ciphertext
    std::string hexCiphertext((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    
    // Convert hex to binary
    std::vector<unsigned char> ciphertext;
    fromHex(hexCiphertext, ciphertext);

    // Decrypt the data
    std::vector<unsigned char> plaintext = decryptAES(ciphertext, key);

    // Write decrypted data to file
    decryptedFile.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());

    std::cout << "Decryption completed. File saved as: " << filePath.string() << std::endl;
    return true;
}
