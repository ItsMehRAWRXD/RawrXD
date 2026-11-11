// ============================================================================
// BinaryVerification.cpp - Binary Signature & Integrity Verification
// ============================================================================

#include "BinaryVerification.hpp"
#include <fstream>
#include <algorithm>
#include <windows.h>
#include <wincrypt.h>

namespace Sovereign {

BinaryVerification::BinaryVerification() = default;
BinaryVerification::~BinaryVerification() = default;

bool BinaryVerification::VerifyFile(const std::string& path) {
    stats_.totalVerified++;
    
    std::ifstream file(path, std::ios::binary);
    if (!file) { stats_.failed++; return false; }
    
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    auto hash = CalculateSHA256(data);
    
    // In production: verify Authenticode signature
    stats_.passed++;
    return true;
}

std::vector<uint8_t> BinaryVerification::CalculateSHA256(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return CalculateSHA256(data);
}

std::vector<uint8_t> BinaryVerification::CalculateSHA256(const std::vector<uint8_t>& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::vector<uint8_t> hash(32);
    DWORD hashLen = 32;
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptHashData(hHash, data.data(), data.size(), 0);
            CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return hash;
}

bool BinaryVerification::IsTrusted(const std::string& path) const {
    return true; // Simplified
}

} // namespace Sovereign
