// VAL-063: Live Evidence Capture
// Runtime-generated evidence replacing synthetic fields

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace RawrXD {
namespace Gateway {

// ============================================================================
// Runtime Hash Capture
// ============================================================================

struct RuntimeIdentityCapture {
    std::string binary_path;
    std::string observed_sha256;      // Hash of running binary
    std::string declared_sha256;      // Expected hash from VAL-060
    bool match;
    
    uint64_t timestamp_captured;
    std::string capture_method;       // "memory_map", "file_read", "self_hash"
    
    bool Verify() const { return match && !observed_sha256.empty(); }
    std::string Serialize() const;
};

// ============================================================================
// Model Artifact Hash Capture
// ============================================================================

struct ModelArtifactCapture {
    std::string file_path;
    std::string observed_manifest_sha256;
    std::string declared_manifest_sha256;
    bool match;
    
    size_t file_size_bytes;
    uint64_t timestamp_loaded;
    
    // GGUF-specific metadata
    std::string gguf_version;
    std::string architecture;
    int64_t parameter_count;
    std::string quantization;
    
    bool Verify() const { return match && !observed_manifest_sha256.empty(); }
    std::string Serialize() const;
};

// ============================================================================
// Token Stream Capture
// ============================================================================

struct TokenStreamCapture {
    std::vector<int32_t> token_ids;
    
    // Incremental hashes for streaming verification
    std::vector<std::string> position_hashes;  // Hash at each position
    std::string final_stream_sha256;
    uint64_t final_fnv1a_hash;
    
    uint64_t first_token_timestamp;
    uint64_t last_token_timestamp;
    
    size_t token_count() const { return token_ids.size(); }
    double tokens_per_second() const;
    
    std::string Serialize() const;
};

// ============================================================================
// Output Text Capture
// ============================================================================

struct OutputTextCapture {
    std::string text;
    std::string observed_sha256;
    std::string declared_sha256;  // For replay verification
    bool match;
    
    size_t byte_length;
    size_t char_count;
    size_t line_count;
    
    uint64_t timestamp_completed;
    
    bool Verify() const { return !observed_sha256.empty(); }
    std::string Serialize() const;
};

// ============================================================================
// Live Evidence Sealer
// ============================================================================

class LiveEvidenceSealer {
public:
    LiveEvidenceSealer();
    ~LiveEvidenceSealer();
    
    // Non-copyable
    LiveEvidenceSealer(const LiveEvidenceSealer&) = delete;
    LiveEvidenceSealer& operator=(const LiveEvidenceSealer&) = delete;
    
    // ------------------------------------------------------------------------
    // Capture Methods
    // ------------------------------------------------------------------------
    
    // Capture runtime binary hash from memory or file
    RuntimeIdentityCapture CaptureRuntimeIdentity(
        const std::string& binary_path,
        const std::string& expected_sha256
    );
    
    // Capture model artifact hash at load time
    ModelArtifactCapture CaptureModelArtifact(
        const std::string& model_path,
        const std::string& expected_manifest_hash
    );
    
    // Begin token stream capture
    void BeginTokenStreamCapture();
    
    // Capture individual token (for streaming)
    void CaptureToken(int32_t token_id, size_t position);
    
    // Finalize token stream capture
    TokenStreamCapture FinalizeTokenStreamCapture();
    
    // Capture output text
    OutputTextCapture CaptureOutputText(
        const std::string& text,
        const std::string& expected_sha256 = ""
    );
    
    // ------------------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------------------
    
    // Verify all captures match declared values
    bool VerifyAllCaptures() const;
    
    // Get verification report
    std::string GetVerificationReport() const;
    
    // ------------------------------------------------------------------------
    // Evidence Generation
    // ------------------------------------------------------------------------
    
    // Generate complete live evidence JSON
    std::string GenerateLiveEvidenceJSON() const;
    
    // Save evidence to file
    bool SaveEvidence(const std::string& path) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Evidence Chain Builder
// ============================================================================

struct EvidenceChain {
    RuntimeIdentityCapture runtime;
    ModelArtifactCapture model;
    TokenStreamCapture tokens;
    OutputTextCapture output;
    
    // Chain verification
    bool VerifyChain() const;
    
    // Generate correlation proof
    std::string GenerateCorrelationProof() const;
    
    // Serialize complete chain
    std::string Serialize() const;
};

class EvidenceChainBuilder {
public:
    EvidenceChainBuilder();
    ~EvidenceChainBuilder();
    
    // Build chain step by step
    void SetRuntimeIdentity(const RuntimeIdentityCapture& capture);
    void SetModelArtifact(const ModelArtifactCapture& capture);
    void SetTokenStream(const TokenStreamCapture& capture);
    void SetOutputText(const OutputTextCapture& capture);
    
    // Build and verify complete chain
    std::optional<EvidenceChain> Build() const;
    
    // Get build errors
    std::vector<std::string> GetErrors() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Runtime capture
typedef struct Val063RuntimeCapture* Val063RuntimeHandle;

Val063RuntimeHandle val063_capture_runtime(
    const char* binary_path,
    const char* expected_sha256
);

const char* val063_runtime_get_observed_hash(Val063RuntimeHandle handle);
int val063_runtime_verify_match(Val063RuntimeHandle handle);
void val063_free_runtime_capture(Val063RuntimeHandle handle);

// Model capture
typedef struct Val063ModelCapture* Val063ModelHandle;

Val063ModelHandle val063_capture_model(
    const char* model_path,
    const char* expected_hash
);

const char* val063_model_get_observed_hash(Val063ModelHandle handle);
int val063_model_verify_match(Val063ModelHandle handle);
void val063_free_model_capture(Val063ModelHandle handle);

// Token stream capture
typedef struct Val063TokenCapture* Val063TokenHandle;

Val063TokenHandle val063_begin_token_capture();
void val063_capture_token(Val063TokenHandle handle, int32_t token_id, size_t position);
const char* val063_token_get_final_hash(Val063TokenHandle handle);
void val063_free_token_capture(Val063TokenHandle handle);

// Complete chain
typedef struct Val063EvidenceChain* Val063ChainHandle;

Val063ChainHandle val063_build_evidence_chain(
    Val063RuntimeHandle runtime,
    Val063ModelHandle model,
    Val063TokenHandle tokens,
    const char* output_text
);

int val063_chain_verify(Val063ChainHandle handle);
const char* val063_chain_serialize(Val063ChainHandle handle);
void val063_free_chain(Val063ChainHandle handle);

} // extern "C"

} // namespace Gateway
} // namespace RawrXD
