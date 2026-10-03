// RAWRXD_GRAPH_RESTORED_001 — Minimal stub for plugin_signature.h
#pragma once
#include <string>
#include <mutex>

namespace RawrXD {

enum class SignatureStatus {
    Valid,
    NoSignature,
    RevokedCertificate,
    UntrustedRoot,
    ExpiredCertificate,
    UnknownError,
    Tampered,
};

struct SignaturePolicy {
    bool requireSignature = false;
    bool requireTrustedRoot = false;
    bool requireRawrXDAuthority = false;
    bool allowExpiredCerts = false;
    bool checkCertRevocation = false;
    bool logBlockedInstalls = false;
    uint32_t maxCertChainDepth = 8;
};

struct TrustedPublisher {
    char thumbprint[64] = {};
    uint64_t addedTimestamp = 0;
};

struct PluginSignatureResult {
    bool valid = false;
    char subjectName[256] = {};
    char issuerName[256] = {};
    char thumbprint[64] = {};
    uint64_t expiryTimestamp = 0;
    bool isRawrXDSigned = false;
    SignatureStatus status = SignatureStatus::UnknownError;
    char detail[256] = {};
    int errorCode = 0;
    char message[256] = {};

    static PluginSignatureResult error(SignatureStatus s, const char* msg) {
        PluginSignatureResult r;
        r.valid = false;
        r.status = s;
        r.errorCode = -1;
        if (msg) {
            std::strncpy(r.detail, msg, sizeof(r.detail) - 1);
            std::strncpy(r.message, msg, sizeof(r.message) - 1);
        }
        return r;
    }
    static PluginSignatureResult ok(const char* msg) {
        PluginSignatureResult r;
        r.valid = true;
        r.status = SignatureStatus::Valid;
        r.errorCode = 0;
        if (msg) {
            std::strncpy(r.detail, msg, sizeof(r.detail) - 1);
            std::strncpy(r.message, msg, sizeof(r.message) - 1);
        }
        return r;
    }
};

namespace Plugin {

constexpr uint32_t MAX_TRUSTED_PUBLISHERS = 64;

struct Stats {
    uint32_t totalVerifications = 0;
    uint32_t validSignatures = 0;
    uint32_t invalidSignatures = 0;
};

class PluginSignatureVerifier {
public:
    using Stats = ::RawrXD::Plugin::Stats;
    static PluginSignatureVerifier& instance();
    PluginSignatureVerifier();
    ~PluginSignatureVerifier();

    bool initialize();
    bool initialize(const SignaturePolicy& policy);
    void shutdown();

    SignaturePolicy createStrictPolicy();
    SignaturePolicy createStandardPolicy();
    SignaturePolicy createRelaxedPolicy();
    SignaturePolicy getPolicy() const;
    void setPolicy(const SignaturePolicy& policy);

    PluginSignatureResult winVerifyTrustCheck(const wchar_t* filePath);
    PluginSignatureResult verifyDLL(const wchar_t* dllPath);
    PluginSignatureResult verifyVSIX(const wchar_t* vsixPath);
    PluginSignatureResult verifyJSModule(const wchar_t* jsPath, const char* expectedHash);
    PluginSignatureResult verifyRawrPackage(const wchar_t* packagePath);
    PluginSignatureResult verify(const wchar_t* packagePath);

    bool shouldAllowInstall(const PluginSignatureResult& result) const;

    bool addTrustedPublisher(const TrustedPublisher& publisher);
    bool removeTrustedPublisher(const char* thumbprint);
    bool isTrustedPublisher(const char* thumbprint) const;
    uint32_t getTrustedPublishers(TrustedPublisher* outPublishers, uint32_t maxCount) const;

    Stats getStats() const;
    void resetStats();

private:
    bool extractCertInfo(const wchar_t* filePath, char* subject, size_t subjectLen,
                         char* issuer, size_t issuerLen, char* thumbprint, uint64_t* expiry);
    bool computeFileSHA256(const wchar_t* filePath, char outHex[65]);

    bool m_initialized;
    uint32_t m_publisherCount;
    SignaturePolicy m_policy;
    TrustedPublisher m_publishers[MAX_TRUSTED_PUBLISHERS];
    Stats m_stats;
    mutable std::mutex m_mutex;
};

} // namespace Plugin

} // namespace RawrXD
