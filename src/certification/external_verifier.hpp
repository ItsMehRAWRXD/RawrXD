// VAL-078: External Verifier Package
// Standalone verification without runtime dependencies

#pragma once

#include <string>
#include <vector>
#include <memory>

namespace RawrXD {
namespace Certification {

// ============================================================================
// External Verifier Architecture
// ============================================================================

/*
Design Principle: Zero Runtime Dependencies

rawrxd.exe (produces evidence)
     |
     | evidence bundle (JSON + hashes)
     v
rawrxd-verify.exe (standalone)
     |
     |-- JSON parser (embedded)
     |-- Crypto library (embedded)
     |-- Hash implementation (embedded)
     |
     v
CERTIFIED / FAILED

No dependency on:
- rawrxd runtime
- inference engine
- model loading
- tensor operations
*/

// ============================================================================
// Minimal Crypto Interface
// ============================================================================

struct MinimalHash {
    static std::string SHA256(const std::string& data);
    static std::string SHA256_File(const std::string& path);
    static bool VerifySHA256(const std::string& data, 
                              const std::string& expected_hash);
};

struct MinimalSignature {
    static bool VerifyEd25519(const std::string& message,
                                const std::string& signature,
                                const std::string& public_key);
    static bool VerifyECDSA(const std::string& message,
                             const std::string& signature,
                             const std::string& public_key);
};

// ============================================================================
// Evidence Bundle Parser
// ============================================================================

struct EvidenceBundle {
    std::string manifest_json;
    std::vector<std::pair<std::string, std::string>> artifacts; // path, hash
    std::string signature;
    std::string public_key;
    
    bool Parse(const std::string& bundle_path);
    bool ValidateStructure() const;
    std::string ComputeRootHash() const;
};

// ============================================================================
// Standalone Verifier
// ============================================================================

struct VerificationConfig {
    bool verify_signatures;
    bool verify_hashes;
    bool verify_chain;
    bool require_timestamp;
    std::vector<std::string> trusted_public_keys;
    
    static VerificationConfig Default();
};

struct StandaloneVerificationResult {
    bool bundle_valid;
    bool manifest_valid;
    bool signatures_valid;
    bool hashes_valid;
    bool chain_valid;
    
    std::string release;
    std::string commit_hash;
    int artifacts_verified;
    int artifacts_failed;
    
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    
    bool IsCertified() const {
        return bundle_valid && manifest_valid && signatures_valid && 
               hashes_valid && chain_valid && errors.empty();
    }
    
    std::string ToJSON() const;
    void PrintReport() const;
};

class StandaloneVerifier {
public:
    StandaloneVerifier();
    ~StandaloneVerifier();
    
    // Initialize with config
    bool Initialize(const VerificationConfig& config);
    
    // Verify evidence bundle
    StandaloneVerificationResult VerifyBundle(const std::string& bundle_path);
    
    // Verify individual components
    bool VerifyManifest(const std::string& manifest_json);
    bool VerifySignature(const EvidenceBundle& bundle);
    bool VerifyArtifactHashes(const EvidenceBundle& bundle);
    bool VerifyChainIntegrity(const EvidenceBundle& bundle);
    
    // Get embedded public keys
    std::vector<std::string> GetEmbeddedPublicKeys() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// CLI Interface
// ============================================================================

class ExternalVerifierCLI {
public:
    // Main entry: rawrxd-verify <bundle_path> [options]
    static int Main(int argc, char* argv[]);
    
    // Commands
    static int CmdVerify(const std::string& bundle_path, 
                         const VerificationConfig& config);
    static int CmdExtract(const std::string& bundle_path,
                          const std::string& output_dir);
    static int CmdInspect(const std::string& bundle_path);
    static int CmdVersion();
    
    // Print usage
    static void PrintUsage();
    static void PrintVersion();
};

// ============================================================================
// Embedded Dependencies
// ============================================================================

// These are minimal implementations embedded in the verifier binary
namespace Embedded {
    // JSON parser (minimal, no external deps)
    class JSONParser {
    public:
        static bool Parse(const std::string& json, 
                          std::map<std::string, std::string>& out);
    };
    
    // Base64 codec
    class Base64 {
    public:
        static std::string Encode(const std::string& data);
        static std::string Decode(const std::string& encoded);
    };
    
    // Hex codec
    class Hex {
    public:
        static std::string Encode(const uint8_t* data, size_t len);
        static std::vector<uint8_t> Decode(const std::string& hex);
    };
}

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Standalone verifier
typedef struct Val078StandaloneVerifier* Val078VerifierHandle;

Val078VerifierHandle val078_verifier_create();
int val078_verifier_initialize(Val078VerifierHandle handle, 
                                  const char* config_json);
int val078_verify_bundle(Val078VerifierHandle handle, 
                          const char* bundle_path);
const char* val078_get_result_json(Val078VerifierHandle handle);
void val078_verifier_destroy(Val078VerifierHandle handle);

// Simple verify
int val078_quick_verify(const char* bundle_path);

} // extern "C"

} // namespace Certification
} // namespace RawrXD
