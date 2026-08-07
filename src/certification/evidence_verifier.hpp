// RC-1.1: Evidence Integrity Verifier
// Third-party verification without development environment

#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>

namespace RawrXD {
namespace Certification {

// ============================================================================
// Verification Result
// ============================================================================

enum class VerificationStatus {
    Pass,
    Fail_HashMismatch,
    Fail_FileMissing,
    Fail_ManifestCorrupt,
    Fail_RootHashInvalid,
    Warning_EvidenceDrift
};

struct ArtifactVerification {
    std::string path;
    std::string expected_hash;
    std::string observed_hash;
    bool verified;
    size_t size_bytes;
};

struct VerificationResult {
    VerificationStatus status;
    std::string release;
    std::string commit_hash;
    
    std::vector<ArtifactVerification> artifacts;
    int total_artifacts;
    int verified_count;
    int failed_count;
    int missing_count;
    
    std::string root_hash_expected;
    std::string root_hash_computed;
    bool root_hash_match;
    
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    
    bool IsPass() const { 
        return status == VerificationStatus::Pass && root_hash_match;
    }
    
    std::string Serialize() const;
};

// ============================================================================
// Evidence Manifest Parser
// ============================================================================

struct EvidenceManifest {
    std::string schema;
    std::string schema_version;
    std::string release;
    std::string release_version;
    std::string commit_hash;
    std::string generated_at;
    std::string manifest_hash;
    std::string root_hash;
    
    struct Artifact {
        std::string path;
        std::string sha256;
        size_t size_bytes;
        std::string gate;
        std::string claim;
    };
    std::vector<Artifact> artifacts;
    
    static std::optional<EvidenceManifest> Load(const std::string& path);
    std::string ComputeRootHash() const;
};

// ============================================================================
// Evidence Verifier
// ============================================================================

class EvidenceVerifier {
public:
    EvidenceVerifier();
    ~EvidenceVerifier();
    
    // Load and verify complete evidence package
    VerificationResult VerifyEvidencePackage(
        const std::string& evidence_directory
    );
    
    // Verify single artifact
    ArtifactVerification VerifyArtifact(
        const std::string& evidence_dir,
        const EvidenceManifest::Artifact& artifact
    );
    
    // Compute root hash from artifacts
    std::string ComputeRootHash(
        const std::string& evidence_dir,
        const EvidenceManifest& manifest
    );
    
    // Check for evidence drift (modifications after certification)
    bool CheckEvidenceDrift(
        const std::string& evidence_directory
    );

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// CLI Verification Tool
// ============================================================================

class VerificationCLI {
public:
    // Main entry point: rawrxd verify --release RC1
    static int Run(int argc, char* argv[]);
    
    // Verify specific release
    static VerificationResult VerifyRelease(const std::string& release);
    
    // Print verification report
    static void PrintReport(const VerificationResult& result);
    
    // Print usage
    static void PrintUsage();
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Verification
typedef struct Val063EvidenceVerifier* Val063VerifierHandle;

Val063VerifierHandle val063_verifier_create();
int val063_verifier_verify_package(
    Val063VerifierHandle handle,
    const char* evidence_directory
);
const char* val063_verifier_get_result_json(Val063VerifierHandle handle);
void val063_verifier_destroy(Val063VerifierHandle handle);

// Quick verify
int val063_quick_verify(const char* evidence_directory);

} // extern "C"

} // namespace Certification
} // namespace RawrXD
