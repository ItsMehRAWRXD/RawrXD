// VAL-081: Reproducible Build Proof
// Binary identity from build inputs

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace RawrXD {
namespace Certification {

// ============================================================================
// Build Input Identity
// ============================================================================

struct SourceCommit {
    std::string hash;
    std::string message;
    std::string author;
    std::string timestamp;
    std::string tree_hash;
    
    std::string ComputeIdentity() const;
    std::string Serialize() const;
};

struct CompilerFingerprint {
    std::string name;
    std::string version;
    std::string path;
    std::string target_triple;
    std::string executable_hash;
    
    std::string ComputeFingerprint() const;
    std::string Serialize() const;
};

struct BuildFlags {
    std::vector<std::string> flags;
    std::map<std::string, std::string> defines;
    std::vector<std::string> include_paths;
    std::vector<std::string> library_paths;
    
    std::string ComputeFlagsHash() const;
    std::string Serialize() const;
};

struct DependencyHashes {
    std::map<std::string, std::string> dependencies; // name -> hash
    std::string lock_file_hash;
    
    std::string ComputeDependenciesHash() const;
    std::string Serialize() const;
};

// ============================================================================
// Build Inputs
// ============================================================================

struct BuildInputs {
    SourceCommit source;
    CompilerFingerprint compiler;
    BuildFlags flags;
    DependencyHashes dependencies;
    std::string build_script_hash;
    
    std::string ComputeInputsHash() const;
    std::string Serialize() const;
};

// ============================================================================
// Binary Identity Proof
// ============================================================================

struct BinaryIdentityProof {
    BuildInputs inputs;
    std::string binary_path;
    std::string binary_hash;
    std::string proof_hash;  // Hash of inputs + binary hash
    
    bool ComputeProof();
    bool VerifyProof() const;
    std::string Serialize() const;
    static std::optional<BinaryIdentityProof> Load(const std::string& path);
};

// ============================================================================
// Reproducibility Verifier
// ============================================================================

class ReproducibilityProofVerifier {
public:
    ReproducibilityProofVerifier();
    ~ReproducibilityProofVerifier();
    
    // Verify that binary matches build inputs
    struct VerificationResult {
        bool source_matches;
        bool compiler_matches;
        bool flags_match;
        bool dependencies_match;
        bool binary_hash_matches;
        bool proof_valid;
        
        std::vector<std::string> differences;
        
        bool IsReproducible() const {
            return source_matches && compiler_matches && flags_match &&
                   dependencies_match && binary_hash_matches && proof_valid;
        }
    };
    
    VerificationResult VerifyReproducibility(
        const BinaryIdentityProof& proof,
        const std::string& actual_binary_path
    );
    
    // Compare two builds
    bool CompareBuilds(
        const BinaryIdentityProof& build1,
        const BinaryIdentityProof& build2
    );
    
    // Generate reproducibility report
    std::string GenerateReport(const VerificationResult& result) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Build Environment Capture
// ============================================================================

class BuildEnvironmentCapture {
public:
    BuildEnvironmentCapture();
    ~BuildEnvironmentCapture();
    
    // Capture complete build environment
    BuildInputs CaptureEnvironment();
    
    // Capture specific components
    SourceCommit CaptureSourceCommit();
    CompilerFingerprint CaptureCompilerFingerprint();
    BuildFlags CaptureBuildFlags();
    DependencyHashes CaptureDependencyHashes();
    
    // Save captured environment
    bool SaveEnvironment(const BuildInputs& inputs, const std::string& path);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Reproducible Build Test Suite
// ============================================================================

struct ReproducibleBuildTestResult {
    std::string test_name;
    bool passed;
    std::string build1_hash;
    std::string build2_hash;
    std::string error_message;
};

class ReproducibleBuildTestSuite {
public:
    ReproducibleBuildTestSuite();
    ~ReproducibleBuildTestSuite();
    
    // Run reproducibility tests
    std::vector<ReproducibleBuildTestResult> RunAllTests();
    
    // Individual tests
    ReproducibleBuildTestResult TestBitIdenticalBuilds();
    ReproducibleBuildTestResult TestSourceDeterminism();
    ReproducibleBuildTestResult TestCompilerDeterminism();
    ReproducibleBuildTestResult TestFlagSensitivity();
    ReproducibleBuildTestResult TestDependencySensitivity();
    
    // Get summary
    struct Summary {
        int total_tests;
        int passed;
        int failed;
        bool fully_reproducible;
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

// Build inputs
typedef struct Val081BuildInputs* Val081InputsHandle;

Val081InputsHandle val081_inputs_capture();
const char* val081_inputs_compute_hash(Val081InputsHandle handle);
void val081_inputs_destroy(Val081InputsHandle handle);

// Binary proof
typedef struct Val081BinaryProof* Val081ProofHandle;

Val081ProofHandle val081_proof_create(Val081InputsHandle inputs, const char* binary_path);
int val081_proof_compute(Val081ProofHandle handle);
const char* val081_proof_get_hash(Val081ProofHandle handle);
void val081_proof_destroy(Val081ProofHandle handle);

// Verification
typedef struct Val081ReproducibilityVerifier* Val081VerifierHandle;

Val081VerifierHandle val081_verifier_create();
int val081_verify_reproducibility(Val081VerifierHandle handle, Val081ProofHandle proof);
const char* val081_verifier_get_report(Val081VerifierHandle handle);
void val081_verifier_destroy(Val081VerifierHandle handle);

} // extern "C"

} // namespace Certification
} // namespace RawrXD
