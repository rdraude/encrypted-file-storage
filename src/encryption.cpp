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
    const size_t AES_BLOCK_SIZE = 16;
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);  // Direct initialization
    if (!RAND_bytes(iv.data(), 16)) throw std::runtime_error("IV generation failed");

    if (!RAND_bytes(iv.data(), 16)) 
        throw std::runtime_error("IV generation failed");
        
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Context creation failed");

    std::vector<unsigned char> ciphertext(plaintext.size() + 16);  // Extra space for padding
    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, (unsigned char*)key.c_str(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end());  // Prepend IV
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}
