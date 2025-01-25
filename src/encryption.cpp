#include "encryption.hpp" 

void generateKey(size_t length, std::string& key) {
    if (length == 0) {
        throw std::invalid_argument("Key length must be greater than 0.");
    }

    if (key.size() != 0) {
        key.clear();
    }
    key.reserve(length);

    std::random_device rd;  // Secure random number generator
    std::mt19937 gen(rd()); // Seed for generator https://en.wikipedia.org/wiki/Mersenne_Twister
    std::uniform_int_distribution<> dis(0, 255); // 2^8 = 256

    for (size_t i = 0; i < length; ++i) {
        key += static_cast<char>(dis(gen)); // Add a randomized byte to the key
    }

    return; //void because we modify key in place
}

void toHex(const std::vector<unsigned char>& data, std::string& hexString) {
    if (hexString.size() != 0) {
        hexString.clear();
    }
    const char* hexChars = "0123456789ABCDEF";

    for (unsigned char byte : data) {
        hexString += hexChars[byte >> 4];  // leftmost four bits
        hexString += hexChars[byte & 0x0F]; // rightmost four bits (and with 00001111)
    }

    return; //void because we modify hexString in place
}

void fromHex(const std::string& hex, std::vector<unsigned char>& result) {
    if (result.size() != 0) {
        result.clear();
    }
    result.reserve(hex.length() / 2);  // 2 hex = 1 byte
    char high, low; 
    unsigned char highHalf, lowHalf;
    for (size_t i = 0; i < hex.length(); i += 2) {
        high = hex[i];
        low = hex[i + 1];
        
        // if it's a digit, convert to int by -'0', else convert to int by -'A' + 10 (assuming uppercase)
        highHalf = (high >= '0' && high <= '9') ? high - '0' : (high - 'A' + 10);
        lowHalf = (low >= '0' && low <= '9') ? low - '0' : (low - 'A' + 10);

        // Combine into a single byte
        result.push_back((highHalf << 4) | lowHalf);
    }
    return; //void because we modify result in place
}

std::vector<unsigned char> encryptAES(const std::vector<unsigned char>& plaintext, const std::string& key) {
    const size_t AES_BLOCK_SIZE = 16; // Assumes key is 16 bytes
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);

    // Generate a random IV (Initialization Vector)
    if (!RAND_bytes(iv.data(), AES_BLOCK_SIZE)) {
        throw std::runtime_error("IV generation failed");
    }

    // Create a new EVP_CIPHER_CTX (context for encryption)
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Context creation failed");
    }

    // Prepare space for the ciphertext, including space for padding
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0;

    // Initialize encryption with AES-128-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, 
                           reinterpret_cast<const unsigned char*>(key.c_str()), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES encryption");
    }

    // Perform encryption
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt plaintext");
    }

    int ciphertext_len = len;

    // Finalize encryption (handles padding)
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }

    ciphertext_len += len;

    // Resize ciphertext vector to the correct length
    ciphertext.resize(ciphertext_len);

    // Prepend IV to the ciphertext
    ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end());

    // Free context
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

std::vector<unsigned char> decryptAES(const std::vector<unsigned char>& ciphertext, const std::string& key) {
    const size_t AES_BLOCK_SIZE = 16; // Assumes key is 16 bytes

    // Handle our prepended Init Vector
    if (ciphertext.size() < AES_BLOCK_SIZE) {
        throw std::invalid_argument("Ciphertext is too short to contain an IV.");
    }
    std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE);
    
    // Extract the actual ciphertext (without the IV)
    std::vector<unsigned char> ciphertext_without_iv(ciphertext.begin() + AES_BLOCK_SIZE, ciphertext.end());

    // Create a new EVP_CIPHER_CTX (context for decryption) (memory allocation) (may abtract out of function to recycle context)
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Context creation failed");
    }

    // Prepare space for the plaintext
    std::vector<unsigned char> plaintext(ciphertext_without_iv.size());
    int len = 0;

    // Initialize decryption with AES-128-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(key.c_str()), iv.data()) != 1) {
                            // Need to reinterpret cast because EVP needs a sequence of bytes (unsigned instead of signed char)
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES decryption");
    }

    // Perform decryption
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext_without_iv.data(), ciphertext_without_iv.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt ciphertext");
    }

    int plaintext_len = len;

    // Finalize decryption (handles padding)
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }

    plaintext_len += len;

    // Resize plaintext vector to the correct length
    plaintext.resize(plaintext_len);

    // Free context
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}
