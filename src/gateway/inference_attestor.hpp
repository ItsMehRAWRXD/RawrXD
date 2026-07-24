// VAL-063: Gateway Attestation Layer
// Proves external requests enter and exit through the validated path

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <optional>

namespace RawrXD {
namespace Gateway {

// Forward declarations
struct SamplingConfig;
struct RuntimeCertificationState;

// ============================================================================
// Request Sealing — Immutable Input Boundary
// ============================================================================

struct GatewayRequestAttestation {
    std::string request_id;           // UUID v4 for traceability
    
    // Input boundary hashes
    std::string input_sha256;         // SHA-256 of prompt bytes
    std::string model_manifest_sha256; // SHA-256 of model manifest
    
    // Execution parameters
    SamplingConfig sampling;
    uint64_t seed;
    
    // Temporal anchoring
    uint64_t timestamp_received;    // Unix nanoseconds
    
    // Canonical hash of this attestation
    std::string attestation_hash;   // SHA-256 of serialized form
    
    bool ComputeHash();
    std::string Serialize() const;
};

struct SamplingConfig {
    float temperature = 0.8f;
    float top_p = 0.95f;
    int32_t top_k = 40;
    float repetition_penalty = 1.0f;
    int32_t max_tokens = 512;
    
    std::string Serialize() const;
    std::string ComputeHash() const;
};

// ============================================================================
// Runtime Certification Binding
// ============================================================================

struct RuntimeCertificationState {
    bool val057_correctness = false;
    bool val058_performance = false;
    bool val059_backend_equivalence = false;
    bool val060_release_ready = false;
    
    std::string val060_commit_hash;   // Git commit of certified build
    std::string val060_binary_sha256; // Binary hash for verification
    
    bool IsReleaseReady() const {
        return val057_correctness && 
               val058_performance && 
               val059_backend_equivalence && 
               val060_release_ready;
    }
    
    std::string Serialize() const;
};

enum class CertificationStatus {
    Valid,           // All gates passed
    Expired,         // Certification timeout
    Incomplete,    // Missing required gates
    Tampered,      // Binary hash mismatch
    Unknown
};

// ============================================================================
// Model Provenance Verification
// ============================================================================

struct ModelProvenance {
    std::string requested_path;
    std::string resolved_path;
    std::string manifest_sha256;
    std::string tensor_hash;          // Hash of loaded tensor data
    int64_t parameter_count;
    std::string architecture;         // e.g., "llama-3-8b"
    
    bool VerifyIntegrity() const;
    std::string Serialize() const;
};

// ============================================================================
// Output Witness Capture
// ============================================================================

struct OutputAttestation {
    uint64_t token_count;
    uint64_t prompt_token_count;
    
    // Fast runtime verification
    uint64_t token_hash_fnv1a;        // FNV-1a of token IDs
    
    // Archival evidence
    std::string text_sha256;          // SHA-256 of generated text
    std::string token_stream_sha256;  // SHA-256 of token ID sequence
    
    // Performance metrics
    uint64_t latency_ms_total;
    uint64_t latency_ms_prompt;
    uint64_t latency_ms_decode;
    
    // Temporal anchoring
    uint64_t timestamp_completed;     // Unix nanoseconds
    
    std::string Serialize() const;
};

// ============================================================================
// Attestation Result
// ============================================================================

enum class AttestationResultCode {
    Success,
    Rejected_RuntimeNotCertified,
    Rejected_ModelManifestMismatch,
    Rejected_ModelIntegrityFailed,
    Rejected_InputValidationFailed,
    Rejected_BypassDetected,
    Error_Internal
};

struct AttestationResult {
    AttestationResultCode code;
    std::string message;
    std::string evidence_path;        // Path to evidence artifact on success
    
    bool IsSuccess() const { return code == AttestationResultCode::Success; }
};

// ============================================================================
// Inference Attestor — Core Class
// ============================================================================

class InferenceAttestor {
public:
    InferenceAttestor();
    ~InferenceAttestor();
    
    // Delete copy/move to ensure single attestation context
    InferenceAttestor(const InferenceAttestor&) = delete;
    InferenceAttestor& operator=(const InferenceAttestor&) = delete;
    
    // ------------------------------------------------------------------------
    // Phase 1: Request Sealing
    // ------------------------------------------------------------------------
    
    // Begin attestation for a new request
    // Computes input hash and validates parameters
    std::optional<GatewayRequestAttestation> BeginRequest(
        const std::string& prompt,
        const std::string& model_path,
        const SamplingConfig& sampling,
        uint64_t seed
    );
    
    // ------------------------------------------------------------------------
    // Phase 2: Runtime Certification Verification
    // ------------------------------------------------------------------------
    
    // Verify the runtime is certified for execution
    // Returns Rejected if any gate is incomplete
    AttestationResult VerifyRuntimeCertification(
        const RuntimeCertificationState& state
    );
    
    // Load certification state from evidence files
    RuntimeCertificationState LoadCertificationState(
        const std::string& evidence_dir
    );
    
    // ------------------------------------------------------------------------
    // Phase 3: Model Provenance Verification
    // ------------------------------------------------------------------------
    
    // Verify model integrity before loading
    // Checks manifest hash and tensor integrity
    AttestationResult VerifyModelProvenance(
        const std::string& model_path,
        const std::string& expected_manifest_hash
    );
    
    // Get provenance info for a model
    ModelProvenance GetModelProvenance(const std::string& model_path);
    
    // ------------------------------------------------------------------------
    // Phase 4: Output Witness Capture
    // ------------------------------------------------------------------------
    
    // Seal the output with cryptographic attestation
    OutputAttestation SealOutput(
        const std::vector<int32_t>& token_ids,
        const std::string& generated_text,
        uint64_t latency_ms_total,
        uint64_t latency_ms_prompt,
        uint64_t latency_ms_decode
    );
    
    // ------------------------------------------------------------------------
    // Phase 5: Evidence Generation
    // ------------------------------------------------------------------------
    
    // Generate complete VAL-063 evidence artifact
    std::string GenerateEvidenceJSON(
        const GatewayRequestAttestation& request,
        const OutputAttestation& output,
        const RuntimeCertificationState& runtime,
        const ModelProvenance& model
    ) const;
    
    // Get attestation chain summary
    std::string GetAttestationChainSummary() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// VAL-063A: Gateway Bypass Detection
// ============================================================================

struct BypassDetectionMetrics {
    uint64_t direct_engine_calls = 0;
    uint64_t gateway_calls = 0;
    uint64_t bypass_attempts = 0;
    
    bool IsBypassDetected() const {
        return direct_engine_calls > 0 || bypass_attempts > 0;
    }
    
    std::string Serialize() const;
};

class BypassDetector {
public:
    static BypassDetector& Instance();
    
    void RecordGatewayCall();
    void RecordDirectEngineCall();
    void RecordBypassAttempt();
    
    BypassDetectionMetrics GetMetrics() const;
    AttestationResult VerifyNoBypass() const;
    
private:
    BypassDetector() = default;
    BypassDetectionMetrics metrics_;
};

// ============================================================================
// VAL-063B: Artifact Identity Lock
// ============================================================================

class ArtifactIdentityLock {
public:
    // Lock a model path to a specific manifest hash
    static bool LockModelPath(
        const std::string& path,
        const std::string& manifest_hash
    );
    
    // Verify loaded model matches locked identity
    static bool VerifyLockedIdentity(
        const std::string& path,
        const std::string& actual_manifest_hash
    );
    
    // Get the locked hash for a path (empty if not locked)
    static std::string GetLockedHash(const std::string& path);
    
    // Clear all locks (for testing)
    static void ClearAllLocks();
};

// ============================================================================
// VAL-063C: Deterministic Replay
// ============================================================================

struct ReplayConfiguration {
    std::string input_sha256;
    std::string model_manifest_sha256;
    uint64_t seed;
    SamplingConfig sampling;
};

class DeterministicReplayVerifier {
public:
    // Record a generation run for later replay verification
    static void RecordRun(
        const ReplayConfiguration& config,
        const std::vector<int32_t>& token_ids
    );
    
    // Verify that replay produces identical output
    static bool VerifyReplay(
        const ReplayConfiguration& config,
        const std::vector<int32_t>& actual_token_ids
    );
    
    // Get expected token hash for a configuration
    static std::optional<uint64_t> GetExpectedTokenHash(
        const ReplayConfiguration& config
    );
    
    // Clear replay history (for testing)
    static void ClearHistory();
};

// ============================================================================
// C API for ABI Stability
// ============================================================================

extern "C" {

// Request attestation
typedef struct Val063RequestAttestation* Val063RequestHandle;

Val063RequestHandle val063_begin_request(
    const char* prompt,
    const char* model_path,
    float temperature,
    float top_p,
    int32_t top_k,
    uint64_t seed
);

void val063_free_request(Val063RequestHandle handle);

const char* val063_get_request_hash(Val063RequestHandle handle);

// Runtime certification
int val063_verify_runtime_certification(
    int val057_pass,
    int val058_pass,
    int val059_pass,
    int val060_pass,
    const char* binary_sha256
);

// Model provenance
int val063_verify_model_provenance(
    const char* model_path,
    const char* expected_manifest_hash
);

// Output attestation
typedef struct Val063OutputAttestation* Val063OutputHandle;

Val063OutputHandle val063_seal_output(
    const int32_t* token_ids,
    size_t token_count,
    const char* generated_text,
    uint64_t latency_ms_total,
    uint64_t latency_ms_prompt,
    uint64_t latency_ms_decode
);

void val063_free_output(Val063OutputHandle handle);

const char* val063_get_output_hash(Val063OutputHandle handle);

// Evidence generation
const char* val063_generate_evidence_json(
    Val063RequestHandle request,
    Val063OutputHandle output
);

// Bypass detection
int val063_verify_no_bypass();

// Replay verification
int val063_verify_replay(
    const char* input_sha256,
    const char* model_sha256,
    uint64_t seed,
    const int32_t* actual_token_ids,
    size_t token_count
);

} // extern "C"

} // namespace Gateway
} // namespace RawrXD
