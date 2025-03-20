#include "hashhelper.h"
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>

std::string computeSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return "";
    }
    
    // Create and initialize the context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return "";
    }
    
    if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    const size_t bufferSize = 8192;
    std::vector<char> buffer(bufferSize);
    
    while (file.good()) {
        file.read(buffer.data(), bufferSize);
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            if (1 != EVP_DigestUpdate(ctx, buffer.data(), bytesRead)) {
                EVP_MD_CTX_free(ctx);
                return "";
            }
        }
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (1 != EVP_DigestFinal_ex(ctx, hash, &hashLen)) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    EVP_MD_CTX_free(ctx);
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hashLen; i++) {
        oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }
    return oss.str();
}
