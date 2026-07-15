// ============================================================================
// RawrXD Immutable Execution Fabric - Hash Chain Manager
// Phase 7C: Execution Verification and Deterministic Replay
// ============================================================================
// C++ wrapper for MASM hash kernel + chain of custody tracking
// ============================================================================

#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <functional>
#include <string>
#include <windows.h>

namespace RawrXD {
namespace Core {

// ============================================================================
// Hash Constants
// ============================================================================

constexpr uint64_t HASH_SEED_DEFAULT = 0x9E3779B97F4A7C15ULL;  // Golden ratio
constexpr uint64_t HASH_SEED_TENSOR  = 0xC2B2AE3D27D4EB4FULL;  // xxHash prime
constexpr uint64_t HASH_SEED_ACTIVATION = 0x165667B19E3779F9ULL;
constexpr uint64_t HASH_SEED_TOKEN   = 0x85EBCA77C2B2AE63ULL;

// ============================================================================
// External MASM Functions
// ============================================================================

extern "C" {
    // Fast 64-bit xxHash-style hash
    uint64_t RawrXD_Hash64(const void* data, size_t len, uint64_t seed);
    
    // Simple FNV-style hash (fallback)
    uint64_t RawrXD_Hash64_Simple(const void* data, size_t len, uint64_t seed);
    
    // Combine two hashes
    uint64_t RawrXD_HashCombine(uint64_t h1, uint64_t h2);
    
    // Deterministic float array hash (normalizes NaN/Inf)
    uint64_t RawrXD_HashFloat32(const float* data, size_t count, uint64_t seed);
}

// ============================================================================
// Hash Types
// ============================================================================

enum class HashStage : uint32_t {
    GGUF_HEADER     = 0,   // Raw GGUF file header
    TENSOR_RAW    = 1,   // Raw tensor data (quantized)
    TENSOR_DEQUANT = 2,  // Dequantized tensor
    EMBEDDING     = 3,   // Token embedding output
    RMSNORM       = 4,   // RMSNorm output
    ATTENTION     = 5,   // Attention output
    FFN           = 6,   // Feed-forward output
    LOGITS        = 7,   // Final logits
    SAMPLER       = 8,   // Sampler state
    TOKEN_STREAM  = 9,   // Generated tokens
    
    COUNT
};

// ============================================================================
// Execution Checkpoint
// ============================================================================

struct ExecutionCheckpoint {
    HashStage stage;
    uint64_t hash_value;
    uint64_t timestamp;      // Cycle counter or timestamp
    uint32_t layer_index;    // For layer-specific checkpoints
    uint32_t token_position; // Position in sequence
    
    // Human-readable description
    char description[64];
    
    ExecutionCheckpoint() = default;
    ExecutionCheckpoint(HashStage s, uint64_t h, uint32_t layer = 0, uint32_t pos = 0, 
                        const char* desc = "")
        : stage(s), hash_value(h), timestamp(0), layer_index(layer), 
          token_position(pos) {
        std::strncpy(description, desc, sizeof(description) - 1);
        description[sizeof(description) - 1] = '\0';
    }
};

// ============================================================================
// Hash Chain Manager
// ============================================================================

class HashChainManager {
public:
    static constexpr size_t MAX_CHECKPOINTS = 1024;
    static constexpr size_t RING_BUFFER_SIZE = 256;
    
    HashChainManager();
    ~HashChainManager();
    
    // Disable copy/move
    HashChainManager(const HashChainManager&) = delete;
    HashChainManager& operator=(const HashChainManager&) = delete;
    
    // Initialize with model hash
    void Initialize(uint64_t model_hash);
    
    // Record checkpoint
    void RecordCheckpoint(HashStage stage, uint64_t hash, 
                          uint32_t layer = 0, uint32_t pos = 0,
                          const char* description = "");
    
    // Hash various data types
    uint64_t HashTensor(const float* data, size_t num_elements, 
                        HashStage stage, uint64_t seed = HASH_SEED_DEFAULT);
    
    uint64_t HashTokens(const int32_t* tokens, size_t count, uint64_t seed = HASH_SEED_DEFAULT);
    
    uint64_t HashBuffer(const void* data, size_t size, uint64_t seed = HASH_SEED_DEFAULT);
    
    // Chain hash: combine with previous hash
    uint64_t ChainHash(uint64_t new_hash);
    
    // Get current chain hash
    uint64_t GetCurrentHash() const { return current_chain_hash_; }
    
    // Get checkpoint count
    size_t GetCheckpointCount() const { return checkpoint_count_; }
    
    // Get checkpoint by index
    const ExecutionCheckpoint* GetCheckpoint(size_t index) const;
    
    // Get last checkpoint
    const ExecutionCheckpoint* GetLastCheckpoint() const;
    
    // Verify chain integrity
    bool VerifyChain() const;
    
    // Export chain to file
    bool ExportChain(const wchar_t* filepath) const;
    bool ExportChain(const char* filepath) const;
    
    // Import chain from file
    bool ImportChain(const wchar_t* filepath);
    bool ImportChain(const char* filepath);
    
    // Reset chain
    void Reset();
    
    // Get stage name
    static const char* GetStageName(HashStage stage);
    
    // Format hash as hex string
    static void FormatHash(uint64_t hash, char* out_buf, size_t buf_size);
    
    // Compare two chains
    static bool CompareChains(const HashChainManager& a, const HashChainManager& b,
                              size_t* first_diff_index = nullptr);

private:
    // Ring buffer of checkpoints
    std::array<ExecutionCheckpoint, RING_BUFFER_SIZE> ring_buffer_;
    size_t ring_head_ = 0;
    size_t ring_count_ = 0;
    
    // Full checkpoint history (if needed for export)
    std::vector<ExecutionCheckpoint> checkpoint_history_;
    size_t checkpoint_count_ = 0;
    
    // Current chain hash
    uint64_t current_chain_hash_ = HASH_SEED_DEFAULT;
    
    // Model hash (root of trust)
    uint64_t model_hash_ = 0;
    
    // Initialized flag
    bool initialized_ = false;
    
    // Thread safety
    SRWLOCK lock_;
    
    void PushCheckpoint(const ExecutionCheckpoint& cp);
};

// ============================================================================
// Async Hash Worker
// ============================================================================

struct HashTicket {
    uint64_t ticket_id;
    uint64_t hash_value;
    bool completed;
    HANDLE event;
    
    HashTicket() : ticket_id(0), hash_value(0), completed(false), event(nullptr) {}
};

struct HashWorkItem {
    uint64_t ticket_id;
    const void* data;
    size_t size;
    uint64_t seed;
    HashStage stage;
    uint32_t layer;
    uint32_t token_pos;
    char description[64];
    bool is_float32;
    size_t float_count;
};

class AsyncHashWorker {
public:
    AsyncHashWorker();
    ~AsyncHashWorker();
    
    // Start/stop worker thread
    bool Start();
    void Stop();
    
    // Submit hash work (non-blocking)
    uint64_t SubmitHash(const void* data, size_t size, uint64_t seed, 
                        HashStage stage, uint32_t layer = 0, uint32_t pos = 0,
                        const char* desc = "");
    
    // Submit float32 hash work
    uint64_t SubmitHashFloat32(const float* data, size_t count, uint64_t seed,
                                 HashStage stage, uint32_t layer = 0, uint32_t pos = 0,
                                 const char* desc = "");
    
    // Wait for ticket completion
    bool WaitForTicket(uint64_t ticket_id, uint64_t* out_hash, uint32_t timeout_ms = 1000);
    
    // Poll for completion (non-blocking)
    bool PollTicket(uint64_t ticket_id, uint64_t* out_hash);
    
    // Get completed count
    size_t GetCompletedCount() const { return completed_count_; }
    
    // Get pending count
    size_t GetPendingCount() const;

private:
    static DWORD WINAPI WorkerThreadProc(LPVOID param);
    void WorkerLoop();
    
    HANDLE worker_thread_ = nullptr;
    HANDLE work_event_ = nullptr;
    bool shutdown_ = false;
    
    // Work queue
    std::vector<HashWorkItem> work_queue_;
    mutable SRWLOCK work_lock_;
    
    // Completed tickets
    std::vector<std::pair<uint64_t, uint64_t>> completed_;  // ticket_id -> hash
    mutable SRWLOCK completed_lock_;
    
    uint64_t next_ticket_id_ = 1;
    size_t completed_count_ = 0;
};

// ============================================================================
// Inference Checkpoint Manager (Hot Path Integration)
// ============================================================================

class InferenceCheckpointManager {
public:
    InferenceCheckpointManager();
    ~InferenceCheckpointManager();
    
    // Initialize for inference session
    void Initialize(uint64_t model_hash, uint64_t inference_id, 
                      const char* model_version, const char* fabric_policy);
    
    // Checkpoint insertion points (called from hot path)
    void CheckpointEmbedding(const float* embeddings, size_t token_count, size_t hidden_dim);
    void CheckpointRMSNorm(const float* output, size_t seq_len, size_t hidden_dim, uint32_t layer);
    void CheckpointAttentionOutput(const float* attn_out, size_t seq_len, size_t hidden_dim, uint32_t layer);
    void CheckpointKVAppend(const float* k_cache, const float* v_cache, size_t kv_len, size_t head_dim, uint32_t layer);
    void CheckpointPostMLP(const float* mlp_out, size_t seq_len, size_t hidden_dim, uint32_t layer);
    void CheckpointLogits(const float* logits, size_t vocab_size, uint32_t token_pos);
    void CheckpointSampler(int32_t selected_token, float temperature, float top_p, int top_k, uint32_t token_pos);
    
    // Wait for all pending checkpoints
    void FlushCheckpoints(uint32_t timeout_ms = 5000);
    
    // Export proof chain
    bool ExportProof(const wchar_t* filepath);
    bool ExportProof(const char* filepath);
    
    // Get current chain hash
    uint64_t GetCurrentChainHash() const { return chain_.GetCurrentHash(); }
    
    // Get inference metadata
    uint64_t GetInferenceId() const { return inference_id_; }
    uint64_t GetModelHash() const { return model_hash_; }

private:
    HashChainManager chain_;
    AsyncHashWorker hash_worker_;
    
    uint64_t inference_id_ = 0;
    uint64_t model_hash_ = 0;
    char model_version_[64] = {};
    char fabric_policy_[64] = {};
    
    // Track pending tickets for flush
    std::vector<uint64_t> pending_tickets_;
    mutable SRWLOCK ticket_lock_;
    
    void RecordTicket(uint64_t ticket_id, HashStage stage, uint32_t layer, uint32_t pos);
};

// ============================================================================
// Forward Declarations
// ============================================================================

class DeterministicRNG;

// ============================================================================
// State Resurrection - KV Cache Identity and Execution Snapshots
// Phase 7C.2: same_state → same_future
// ============================================================================

// KV Cache Identity - cryptographic fingerprint of KV state
struct KVCacheIdentity {
    uint64_t k_hash;           // Hash of K cache
    uint64_t v_hash;           // Hash of V cache
    uint64_t combined_hash;    // HashCombine(k_hash, v_hash)
    uint32_t layer_index;      // Which layer
    uint32_t seq_length;       // Current sequence length
    uint32_t head_dim;         // Head dimension
    uint32_t num_heads;        // Number of heads
    
    KVCacheIdentity() : k_hash(0), v_hash(0), combined_hash(0),
                        layer_index(0), seq_length(0), head_dim(0), num_heads(0) {}
    
    // Compute identity from KV cache data
    void Compute(const float* k_cache, const float* v_cache,
                 uint32_t layer, uint32_t seq_len, uint32_t heads, uint32_t dim,
                 uint64_t seed = HASH_SEED_DEFAULT);
    
    // Verify identity matches data
    bool Verify(const float* k_cache, const float* v_cache,
                uint32_t seq_len, uint32_t heads, uint32_t dim) const;
};

// Sampler State Seal - deterministic RNG + sampling params
struct SamplerStateSeal {
    uint64_t rng_state_hash;     // Hash of RNG state
    uint64_t logits_hash;        // Hash of input logits
    float temperature;
    float top_p;
    int32_t top_k;
    uint32_t token_position;
    int32_t selected_token;
    
    SamplerStateSeal() : rng_state_hash(0), logits_hash(0), temperature(1.0f),
                         top_p(1.0f), top_k(0), token_position(0), selected_token(0) {}
    
    // Compute seal from sampler state
    void Compute(const DeterministicRNG& rng, const float* logits, size_t vocab_size,
                 float temp, float tp, int tk, uint32_t pos, int32_t token);
    
    // Verify seal matches
    bool Verify(const DeterministicRNG& rng, const float* logits, size_t vocab_size) const;
};

// Execution Snapshot - complete resumable state
#pragma pack(push, 1)
struct ExecutionSnapshot {
    // Header
    uint32_t magic;              // 'SNAP' = 0x50414E53
    uint32_t version;            // 1
    uint64_t snapshot_id;        // Unique ID
    uint64_t timestamp;        // Creation time
    
    // Model identity
    uint64_t model_hash;
    char model_version[64];
    
    // Execution state
    uint64_t chain_tip_hash;     // Current chain hash
    uint32_t token_position;     // Position in sequence
    uint32_t num_layers;         // Number of transformer layers
    
    // KV cache identities (one per layer)
    static constexpr uint32_t MAX_LAYERS = 128;
    KVCacheIdentity kv_identities[MAX_LAYERS];
    
    // Sampler state
    SamplerStateSeal sampler_seal;
    
    // Prompt hash (for verification)
    uint64_t prompt_hash;
    
    // RNG state for resumption
    uint64_t rng_state;
    uint64_t rng_inc;
    
    // Final chain hash (for RunA/RunB comparison)
    uint64_t final_chain_hash;
    
    ExecutionSnapshot() : magic(0x50414E53), version(1), snapshot_id(0),
                          timestamp(0), model_hash(0), chain_tip_hash(0),
                          token_position(0), num_layers(0), prompt_hash(0),
                          rng_state(0), rng_inc(0), final_chain_hash(0) {
        std::memset(model_version, 0, sizeof(model_version));
    }
};
#pragma pack(pop)

// State Resurrection Manager
class StateResurrectionManager {
public:
    StateResurrectionManager();
    ~StateResurrectionManager();
    
    // Initialize with checkpoint manager reference
    void Initialize(InferenceCheckpointManager* checkpoint_mgr);
    
    // Capture snapshot at current execution point
    ExecutionSnapshot CaptureSnapshot(
        const float* const* k_caches,          // Array of K cache pointers per layer
        const float* const* v_caches,          // Array of V cache pointers per layer
        const KVCacheIdentity* kv_ids,         // Pre-computed identities
        uint32_t num_layers,
        uint32_t seq_length,
        const SamplerStateSeal& sampler,
        const DeterministicRNG& rng,
        uint64_t prompt_hash);
    
    // Save snapshot to file
    bool SaveSnapshot(const ExecutionSnapshot& snapshot, const wchar_t* filepath);
    bool SaveSnapshot(const ExecutionSnapshot& snapshot, const char* filepath);
    
    // Load snapshot from file
    bool LoadSnapshot(const wchar_t* filepath, ExecutionSnapshot* out_snapshot);
    bool LoadSnapshot(const char* filepath, ExecutionSnapshot* out_snapshot);
    
    // Verify snapshot integrity
    bool VerifySnapshot(const ExecutionSnapshot& snapshot,
                        const float* const* k_caches,
                        const float* const* v_caches) const;
    
    // Restore RNG state from snapshot
    void RestoreRNG(DeterministicRNG* rng, const ExecutionSnapshot& snapshot) const;
    
    // Get snapshot hash for chain
    uint64_t HashSnapshot(const ExecutionSnapshot& snapshot) const;
    
    // Compare two snapshots for identity
    static bool AreIdentical(const ExecutionSnapshot& a, const ExecutionSnapshot& b);

private:
    InferenceCheckpointManager* checkpoint_mgr_ = nullptr;
};

// ============================================================================
// Resume Test - Verify same_state → same_future
// ============================================================================

class ResumeTest {
public:
    // Run A: Execute for N tokens, save snapshot
    struct RunAResult {
        ExecutionSnapshot snapshot;
        std::vector<int32_t> tokens_generated;
        uint64_t final_chain_hash;
        bool success;
    };
    
    // Run B: Restore snapshot, continue for M tokens
    struct RunBResult {
        std::vector<int32_t> tokens_generated;
        uint64_t final_chain_hash;
        bool success;
    };
    
    // Execute resume test
    static bool ExecuteResumeTest(
        // Run A parameters
        const char* model_path,
        const char* prompt,
        uint32_t tokens_a,
        
        // Run B parameters
        uint32_t tokens_b,
        
        // Results
        RunAResult* out_a,
        RunBResult* out_b);
    
    // Verify results match
    static bool VerifyIdenticalFutures(const RunAResult& a, const RunBResult& b);
    
    // Print test report
    static void PrintReport(const RunAResult& a, const RunBResult& b);
};

// ============================================================================
// Deterministic RNG (PCG)
// ============================================================================

class DeterministicRNG {
public:
    DeterministicRNG();
    explicit DeterministicRNG(uint64_t seed);
    
    // Seed the RNG
    void Seed(uint64_t seed);
    
    // Get next random number
    uint32_t NextUint32();
    uint64_t NextUint64();
    
    // Get float in [0, 1)
    float NextFloat();
    
    // Get float in [min, max)
    float NextFloatRange(float min, float max);
    
    // Get current state (for serialization)
    uint64_t GetState() const { return state_; }
    
    // Set state (for deserialization)
    void SetState(uint64_t state) { state_ = state; }
    
    // Hash of current state
    uint64_t GetStateHash() const;

private:
    uint64_t state_ = 0;
    uint64_t inc_ = 1;
    
    static constexpr uint64_t PCG_MULTIPLIER = 6364136223846793005ULL;
    static constexpr uint64_t PCG_INCREMENT = 1442695040888963407ULL;
};

// ============================================================================
// Replay File Format
// ============================================================================

#pragma pack(push, 1)

struct ReplayFileHeader {
    uint32_t magic;           // 'RAWR' = 0x52415752
    uint32_t version;         // 1
    uint64_t timestamp;       // File creation time
    uint64_t model_hash;      // Hash of model file
    uint64_t seed;            // RNG seed
    uint32_t num_checkpoints;
    uint32_t reserved;
    
    ReplayFileHeader() : magic(0x52415752), version(1), timestamp(0),
                         model_hash(0), seed(0), num_checkpoints(0), reserved(0) {}
};

struct ReplayCheckpointEntry {
    uint32_t stage;           // HashStage
    uint64_t hash_value;
    uint64_t timestamp;
    uint32_t layer_index;
    uint32_t token_position;
    char description[64];
};

#pragma pack(pop)

// ============================================================================
// Replay Manager
// ============================================================================

class ReplayManager {
public:
    ReplayManager();
    ~ReplayManager();
    
    // Start recording
    bool StartRecording(const wchar_t* filepath, uint64_t model_hash, uint64_t seed);
    bool StartRecording(const char* filepath, uint64_t model_hash, uint64_t seed);
    
    // Stop recording
    void StopRecording();
    
    // Load replay
    bool LoadReplay(const wchar_t* filepath);
    bool LoadReplay(const char* filepath);
    
    // Get next expected checkpoint (for verification)
    bool GetNextExpectedCheckpoint(ExecutionCheckpoint* out_cp);
    
    // Verify current checkpoint against replay
    bool VerifyCheckpoint(const ExecutionCheckpoint& cp);
    
    // Is recording?
    bool IsRecording() const { return is_recording_; }
    
    // Is replaying?
    bool IsReplaying() const { return is_replaying_; }
    
    // Get replay info
    uint64_t GetReplayModelHash() const { return header_.model_hash; }
    uint64_t GetReplaySeed() const { return header_.seed; }
    uint32_t GetReplayCheckpointCount() const { return header_.num_checkpoints; }
    
    // Reset
    void Reset();

private:
    HANDLE file_handle_ = INVALID_HANDLE_VALUE;
    ReplayFileHeader header_;
    std::vector<ReplayCheckpointEntry> replay_checkpoints_;
    size_t replay_position_ = 0;
    bool is_recording_ = false;
    bool is_replaying_ = false;
};

// ============================================================================
// Utility Functions
// ============================================================================

// Quick hash of file
uint64_t HashFile(const wchar_t* filepath, uint64_t seed = HASH_SEED_DEFAULT);
uint64_t HashFile(const char* filepath, uint64_t seed = HASH_SEED_DEFAULT);

// Hash of GGUF model (header + tensor metadata)
uint64_t HashGGUFModel(const wchar_t* filepath);
uint64_t HashGGUFModel(const char* filepath);

// Format hash for display
std::string FormatHashString(uint64_t hash);

// Verify two executions match
bool VerifyExecutionMatch(const HashChainManager& exec1, const HashChainManager& exec2);

} // namespace Core
} // namespace RawrXD
