// VAL-082: Certification Revocation Model
// Production distribution with revocation support

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Certification {

// ============================================================================
// Revocation Types
// ============================================================================

enum class RevocationReason {
    SECURITY_VULNERABILITY,
    CRITICAL_BUG,
    COMPROMISED_KEY,
    DEPRECATED_VERSION,
    POLICY_VIOLATION,
    OTHER
};

enum class RevocationSeverity {
    CRITICAL,   // Immediate revocation, all usage blocked
    HIGH,       // Revoke for new deployments
    MEDIUM,     // Deprecate, recommend upgrade
    LOW         // Advisory only
};

// ============================================================================
// Revocation Entry
// ============================================================================

struct RevocationEntry {
    std::string artifact_hash;
    std::string revocation_id;
    RevocationReason reason;
    RevocationSeverity severity;
    std::string timestamp;
    std::string description;
    std::string advisory_url;
    
    // Signature
    std::string signed_by;
    std::string signature;
    
    bool IsValid() const;
    std::string Serialize() const;
    static std::optional<RevocationEntry> Deserialize(const std::string& data);
};

// ============================================================================
// Revocation List
// ============================================================================

class RevocationList {
public:
    RevocationList();
    ~RevocationList();
    
    // Load revocation list
    bool Load(const std::string& path);
    bool LoadFromURL(const std::string& url);
    
    // Check if artifact is revoked
    bool IsRevoked(const std::string& artifact_hash) const;
    std::optional<RevocationEntry> GetRevocationInfo(
        const std::string& artifact_hash
    ) const;
    
    // Get all revocations
    std::vector<RevocationEntry> GetAllRevocations() const;
    std::vector<RevocationEntry> GetRevocationsBySeverity(
        RevocationSeverity severity
    ) const;
    
    // Update list
    bool UpdateList(const std::string& source);
    
    // Verify list signature
    bool VerifyListSignature(const std::string& public_key) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Trust Decision Engine
// ============================================================================

struct TrustDecision {
    bool trusted;
    bool valid_signature;
    bool valid_provenance;
    bool not_revoked;
    RevocationSeverity highest_severity;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    
    bool IsTrusted() const {
        return trusted && valid_signature && valid_provenance && not_revoked;
    }
};

class TrustDecisionEngine {
public:
    TrustDecisionEngine();
    ~TrustDecisionEngine();
    
    // Evaluate trust
    TrustDecision EvaluateTrust(
        const std::string& artifact_hash,
        const RevocationList& revocation_list
    );
    
    // Check artifact
    TrustDecision CheckArtifact(
        const std::string& artifact_path,
        const RevocationList& revocation_list
    );
    
    // Policy configuration
    void SetPolicy(RevocationSeverity minimum_severity);
    void RequireOnlineVerification(bool required);
    void SetMaxRevocationListAge(uint64_t max_age_seconds);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Revocation Publisher
// ============================================================================

class RevocationPublisher {
public:
    RevocationPublisher();
    ~RevocationPublisher();
    
    // Publish revocation
    bool PublishRevocation(
        const RevocationEntry& entry,
        const std::string& signing_key
    );
    
    // Update revocation list
    bool UpdateRevocationList(
        const std::vector<RevocationEntry>& entries,
        const std::string& output_path
    );
    
    // Generate CRL (Certificate Revocation List) format
    std::string GenerateCRL(
        const std::vector<RevocationEntry>& entries
    ) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Online/Offline Verification
// ============================================================================

class OnlineVerificationClient {
public:
    OnlineVerificationClient();
    ~OnlineVerificationClient();
    
    // Query revocation status online
    bool QueryRevocationStatus(const std::string& artifact_hash);
    
    // Download latest revocation list
    bool DownloadRevocationList(const std::string& output_path);
    
    // Configure
    void SetEndpoint(const std::string& url);
    void SetTimeout(uint64_t timeout_ms);
    void SetCacheDuration(uint64_t cache_seconds);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Revocation Test Suite
// ============================================================================

struct RevocationTestResult {
    std::string test_name;
    bool passed;
    std::string revoked_artifact;
    std::string error_message;
};

class RevocationTestSuite {
public:
    RevocationTestSuite();
    ~RevocationTestSuite();
    
    // Run revocation tests
    std::vector<RevocationTestResult> RunAllTests();
    
    // Individual tests
    RevocationTestResult TestRevocationDetection();
    RevocationTestResult TestCriticalRevocationBlocks();
    RevocationTestResult TestOfflineVerification();
    RevocationTestResult TestRevocationListUpdate();
    RevocationTestResult TestSignatureVerification();
    
    // Get summary
    struct Summary {
        int total_tests;
        int passed;
        int failed;
        bool revocation_working;
    };
    Summary GetSummary() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Revocation list
typedef struct Val082RevocationList* Val082ListHandle;

Val082ListHandle val082_list_create();
int val082_list_load(Val082ListHandle handle, const char* path);
int val082_is_revoked(Val082ListHandle handle, const char* artifact_hash);
void val082_list_destroy(Val082ListHandle handle);

// Trust decision
typedef struct Val082TrustEngine* Val082EngineHandle;

Val082EngineHandle val082_engine_create();
int val082_evaluate_trust(
    Val082EngineHandle handle,
    Val082ListHandle list,
    const char* artifact_hash
);
const char* val082_get_trust_decision(Val082EngineHandle handle);
void val082_engine_destroy(Val082EngineHandle handle);

} // extern "C"

} // namespace Certification
} // namespace RawrXD
