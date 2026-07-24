// ============================================================================
// BinaryVerification.hpp - Binary Signature & Integrity Verification
// ============================================================================

#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace Sovereign {

struct BinarySignature {
    std::string filePath;
    std::vector<uint8_t> sha256;
    std::vector<uint8_t> signature;
    std::string signer;
    uint64_t timestamp;
    bool isValid;
};

class BinaryVerification {
public:
    BinaryVerification();
    ~BinaryVerification();

    bool VerifyFile(const std::string& path);
    bool VerifySignature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& publicKey);
    std::vector<uint8_t> CalculateSHA256(const std::string& path);
    std::vector<uint8_t> CalculateSHA256(const std::vector<uint8_t>& data);
    
    bool IsTrusted(const std::string& path) const;
    void AddTrustedSigner(const std::string& fingerprint);
    void RemoveTrustedSigner(const std::string& fingerprint);
    
    struct VerificationStats {
        uint64_t totalVerified;
        uint64_t passed;
        uint64_t failed;
        uint64_t skipped;
    };
    VerificationStats GetStats() const { return stats_; }

private:
    std::vector<std::string> trustedSigners_;
    VerificationStats stats_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
