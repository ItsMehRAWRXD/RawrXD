// RC-1.1: Replay Identity Expansion
// Extended replay identity including computational state

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace RawrXD {
namespace Gateway {

// ============================================================================
// Extended Replay Identity
// ============================================================================

struct ReplayIdentity {
    // Input identity
    std::string prompt_hash;           // SHA-256 of input text
    std::string prompt_preview;        // First 100 chars for debugging
    
    // Configuration identity
    std::string configuration_hash;    // Hash of all sampling parameters
    float temperature;
    float top_p;
    int32_t top_k;
    float repetition_penalty;
    int32_t max_tokens;
    
    // Model identity
    std::string model_hash;            // Full model manifest hash
    std::string model_path;
    std::string architecture;
    std::string quantization;
    
    // Runtime identity
    std::string runtime_hash;          // Binary hash
    std::string runtime_version;
    std::string commit_hash;
    
    // Execution state
    uint64_t seed;
    std::string sampler_state;         // Serialized sampler internal state
    std::string kv_state_digest;       // Hash of KV cache state (if resuming)
    
    // Context for multi-turn
    std::string context_hash;          // Hash of conversation history
    uint32_t turn_number;
    
    // Canonical hash of complete identity
    std::string identity_hash;
    
    // Methods
    bool ComputeIdentityHash();
    std::string Serialize() const;
    static std::optional<ReplayIdentity> Deserialize(const std::string& data);
    
    bool operator==(const ReplayIdentity& other) const;
    bool operator!=(const ReplayIdentity& other) const {
        return !(*this == other);
    }
};

// ============================================================================
// Computational State Capture
// ============================================================================

struct ComputationalState {
    // RNG state
    std::vector<uint8_t> rng_state;
    uint64_t rng_position;
    
    // Sampler state
    float current_temperature;
    float current_top_p;
    std::vector<float> token_scores;  // Last computed logits
    
    // KV cache state (for resumable generation)
    std::string kv_cache_digest;         // Hash of cache contents
    uint32_t cache_sequence_length;
    bool cache_valid;
    
    // Layer states (for debugging)
    std::vector<std::string> layer_output_digests;
    
    std::string Serialize() const;
    std::string ComputeDigest() const;
};

// ============================================================================
// Replay Verifier Extended
// ============================================================================

struct ReplayVerificationResult {
    bool identity_match;
    bool output_match;
    bool computational_state_match;
    bool deterministic;
    
    std::string expected_identity_hash;
    std::string actual_identity_hash;
    std::string expected_output_hash;
    std::string actual_output_hash;
    
    std::vector<std::string> differences;
    std::string Serialize() const;
};

class ExtendedReplayVerifier {
public:
    ExtendedReplayVerifier();
    ~ExtendedReplayVerifier();
    
    // Record complete execution state
    void RecordExecution(
        const ReplayIdentity& identity,
        const ComputationalState& state,
        const std::vector<int32_t>& output_tokens
    );
    
    // Verify replay with extended identity
    ReplayVerificationResult VerifyReplay(
        const ReplayIdentity& identity,
        const std::vector<int32_t>& actual_output
    ) const;
    
    // Verify computational state equivalence
    bool VerifyComputationalState(
        const ComputationalState& expected,
        const ComputationalState& actual
    ) const;
    
    // Get expected output for identity
    std::optional<std::vector<int32_t>> GetExpectedOutput(
        const ReplayIdentity& identity
    ) const;
    
    // Generate replay evidence
    std::string GenerateReplayEvidence(
        const ReplayIdentity& identity,
        const ReplayVerificationResult& result
    ) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// State Serialization
// ============================================================================

class StateSerializer {
public:
    // Serialize RNG state portably
    static std::string SerializeRNGState(const std::vector<uint8_t>& state);
    static std::vector<uint8_t> DeserializeRNGState(const std::string& data);
    
    // Serialize KV cache state
    static std::string SerializeKVCacheState(
        const std::vector<float>& key_cache,
        const std::vector<float>& value_cache
    );
    
    // Compute state digest
    static std::string ComputeStateDigest(const std::string& serialized_state);
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Replay identity
typedef struct Val063ReplayIdentity* Val063ReplayIdHandle;

Val063ReplayIdHandle val063_replay_identity_create();
void val063_replay_identity_set_prompt_hash(Val063ReplayIdHandle handle, const char* hash);
void val063_replay_identity_set_config(Val063ReplayIdHandle handle, float temp, float top_p, int top_k);
void val063_replay_identity_set_model_hash(Val063ReplayIdHandle handle, const char* hash);
void val063_replay_identity_set_runtime_hash(Val063ReplayIdHandle handle, const char* hash);
void val063_replay_identity_set_seed(Val063ReplayIdHandle handle, uint64_t seed);
const char* val063_replay_identity_compute_hash(Val063ReplayIdHandle handle);
void val063_replay_identity_destroy(Val063ReplayIdHandle handle);

// Extended replay verification
typedef struct Val063ExtendedReplay* Val063ReplayHandle;

Val063ReplayHandle val063_extended_replay_create();
void val063_extended_replay_record(
    Val063ReplayHandle handle,
    Val063ReplayIdHandle identity,
    const int32_t* tokens,
    size_t token_count
);
int val063_extended_replay_verify(
    Val063ReplayHandle handle,
    Val063ReplayIdHandle identity,
    const int32_t* actual_tokens,
    size_t token_count
);
const char* val063_extended_replay_get_result(Val063ReplayHandle handle);
void val063_extended_replay_destroy(Val063ReplayHandle handle);

} // extern "C"

} // namespace Gateway
} // namespace RawrXD
