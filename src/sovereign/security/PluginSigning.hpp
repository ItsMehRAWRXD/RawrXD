// ============================================================================
// PluginSigning.hpp - Plugin Signing & Verification
// ============================================================================

#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace Sovereign {

struct PluginManifest {
    std::string id;
    std::string name;
    std::string version;
    std::string author;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> signature;
    std::string hash;
};

class PluginSigning {
public:
    PluginSigning();
    ~PluginSigning();

    bool SignPlugin(const std::string& pluginPath, const std::vector<uint8_t>& privateKey);
    bool VerifyPlugin(const std::string& pluginPath);
    bool VerifyPlugin(const PluginManifest& manifest);
    bool GenerateKeyPair(std::vector<uint8_t>& publicKey, std::vector<uint8_t>& privateKey);
    
    void AddTrustedPublisher(const std::string& publisher, const std::vector<uint8_t>& publicKey);
    bool IsPublisherTrusted(const std::string& publisher) const;

    struct SigningStats {
        uint64_t totalSigned;
        uint64_t totalVerified;
        uint64_t passed;
        uint64_t failed;
    };
    SigningStats GetStats() const { return stats_; }

private:
    struct TrustedPublisher {
        std::string name;
        std::vector<uint8_t> publicKey;
    };
    std::vector<TrustedPublisher> trustedPublishers_;
    SigningStats stats_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
