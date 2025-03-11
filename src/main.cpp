#include <iostream>
#include "securefile.hpp"
#include "encryption.hpp"

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <encrypt/decrypt> <filename> <key>\n";
        return 1;
    }

    std::string operation = argv[1];
    std::string filename = argv[2];
    std::string key = argv[3];

    try {
        if (operation == "encrypt") {
            if (encryptFile(filename, key)) {
                std::cout << "File successfully encrypted.\n";
            } else {
                std::cerr << "Encryption failed.\n";
                return 1;
            }
        } else if (operation == "decrypt") {
            if (decryptFile(filename, key)) {
                std::cout << "File successfully decrypted.\n";
            } else {
                std::cerr << "Decryption failed.\n";
                return 1;
            }
        } else {
            std::cerr << "Invalid operation. Use 'encrypt' or 'decrypt'.\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
