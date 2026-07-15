// Phase M.3/5: Advanced Inference Features - Speculative Decoding
// RawrXD Speculative Decoder - Accelerated inference via draft model

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <queue>
#include <functional>
#include <math>

namespace RawrXD {
namespace Advanced {

// Speculative decoding configuration
struct SpeculativeConfig {
    // Draft model settings
    std::string draft_model_path;          // Path to smaller draft model
    uint32_t draft_model_layers = 12;      // Draft model layer count
    uint32_t draft_model_heads = 12;       // Draft model attention heads
    
    // Speculation settings
    uint32_t max_draft_tokens = 5;         // Maximum tokens to draft
    uint32_t min_draft_tokens = 1;         // Minimum tokens to draft
    float acceptance_threshold = 0.6f;     // Minimum acceptance rate to continue
    
    // Adaptive settings
    bool adaptive_speculation = true;      // Adjust based on acceptance rate
    uint32_t window_size = 20;             // Window for acceptance rate calculation
    float target_acceptance = 0.7f;        // Target acceptance rate
    
    // Performance settings
    bool use_gpu_for_draft = true;         // Run draft model on GPU
    uint32_t draft_gpu_device = 0;         // GPU device for draft model
    uint32_t num_draft_threads = 2;        // Threads for draft model
    
    // Verification settings
    bool verify_logits = true;             // Verify token probabilities
    float temperature = 1.0f;              // Temperature for sampling
    uint32_t top_k = 50;                   // Top-k for draft sampling
    float top_p = 0.9f;                    // Top-p for draft sampling
};

// Token acceptance result
struct AcceptanceResult {
    uint32_t accepted_count;               // Number of accepted tokens
    uint32_t rejected_position;            // Position of first rejection (if any)
    std::vector<uint32_t> accepted_tokens;
    std::vector<float> acceptance_probs;  // Probability of each acceptance
    float total_speedup;                   // Measured speedup
    bool all_accepted;                     // All tokens accepted
};

// Draft token candidate
struct DraftCandidate {
    uint32_t token_id;
    float probability;
    float logit;
    std::vector<float> logits;             // Full logits for verification
};

// Speculative decoding statistics
struct SpeculativeStats {
    uint64_t total_draft_attempts;         // Total speculation attempts
    uint64_t total_draft_tokens;           // Total tokens drafted
    uint64_t total_accepted_tokens;        // Total tokens accepted
    uint64_t total_rejected_tokens;        // Total tokens rejected
    
    float acceptance_rate;                 // Overall acceptance rate
    float average_draft_length;            // Average tokens per draft
    float average_accepted_length;         // Average accepted per draft
    float speedup_ratio;                   // Measured speedup vs baseline
    
    uint32_t current_draft_length;         // Current adaptive draft length
    float recent_acceptance_rate;          // Acceptance rate over window
    
    std::chrono::milliseconds draft_time_ms;    // Time spent in draft model
    std::chrono::milliseconds verify_time_ms;   // Time spent in verification
    std::chrono::milliseconds total_time_ms;    // Total time
};

// Speculative decoder interface
class ISpeculativeDecoder {
public:
    virtual ~ISpeculativeDecoder() = default;
    
    // Initialization
    virtual bool Initialize(const SpeculativeConfig& config) = 0;
    virtual void Shutdown() = 0;
    
    // Core speculative decoding
    virtual std::vector<uint32_t> GenerateWithSpeculation(
        const std::vector<uint32_t>& prompt_tokens,
        uint32_t max_new_tokens) = 0;
    
    // Single speculation step
    virtual AcceptanceResult SpeculateAndVerify(
        const std::vector<uint32_t>& context,
        uint32_t num_draft_tokens) = 0;
    
    // Draft model operations
    virtual std::vector<DraftCandidate> DraftTokens(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens) = 0;
    
    // Verification
    virtual AcceptanceResult VerifyTokens(
        const std::vector<uint32_t>& context,
        const std::vector<DraftCandidate>& draft_tokens) = 0;
    
    // Adaptive control
    virtual void UpdateAdaptiveParameters(const AcceptanceResult& result) = 0;
    virtual uint32_t GetOptimalDraftLength() const = 0;
    
    // Statistics
    virtual SpeculativeStats GetStatistics() const = 0;
    virtual void ResetStatistics() = 0;
    
    // Configuration
    virtual const SpeculativeConfig& GetConfig() const = 0;
    virtual bool UpdateConfig(const SpeculativeConfig& config) = 0;
    
    // Status
    virtual bool IsInitialized() const = 0;
    virtual bool IsDraftModelLoaded() const = 0;
    virtual std::string GetStatus() const = 0;
};

// Lookahead speculative decoding (advanced)
class ILookaheadDecoder {
public:
    virtual ~ILookaheadDecoder() = default;
    
    // Initialize with n-gram pool
    virtual bool Initialize(uint32_t n_gram_size = 5, uint32_t max_pool_size = 10000) = 0;
    
    // Update n-gram pool from generated text
    virtual void UpdateNGramPool(const std::vector<uint32_t>& tokens) = 0;
    
    // Find matching n-grams
    virtual std::vector<std::vector<uint32_t>> FindMatches(
        const std::vector<uint32_t>& context,
        uint32_t max_matches = 3) = 0;
    
    // Generate with lookahead
    virtual std::vector<uint32_t> GenerateWithLookahead(
        const std::vector<uint32_t>& prompt_tokens,
        uint32_t max_new_tokens) = 0;
};

// Medusa-style speculative decoding (tree-based)
class IMedusaDecoder {
public:
    virtual ~IMedusaDecoder() = default;
    
    // Initialize with tree attention
    virtual bool Initialize(const std::string& tree_attention_path) = 0;
    
    // Generate candidate tree
    virtual std::vector<std::vector<uint32_t>> GenerateCandidateTree(
        const std::vector<uint32_t>& context,
        uint32_t max_depth = 4) = 0;
    
    // Verify tree with tree attention
    virtual AcceptanceResult VerifyTree(
        const std::vector<uint32_t>& context,
        const std::vector<std::vector<uint32_t>>& candidate_tree) = 0;
    
    // Get tree attention mask
    virtual std::vector<std::vector<bool>> GetTreeAttentionMask(
        const std::vector<std::vector<uint32_t>>& tree) = 0;
};

// Speculative decoder factory
class SpeculativeDecoderFactory {
public:
    // Create standard speculative decoder
    static std::unique_ptr<ISpeculativeDecoder> CreateDecoder(
        const SpeculativeConfig& config);
    
    // Create lookahead decoder
    static std::unique_ptr<ILookaheadDecoder> CreateLookaheadDecoder();
    
    // Create Medusa decoder
    static std::unique_ptr<IMedusaDecoder> CreateMedusaDecoder();
    
    // Check if speculative decoding is beneficial
    static bool IsBeneficial(uint32_t prompt_length, uint32_t target_length);
    
    // Estimate speedup
    static float EstimateSpeedup(float acceptance_rate, uint32_t draft_length);
};

// Draft model interface (simplified model for fast drafting)
class IDraftModel {
public:
    virtual ~IDraftModel() = default;
    
    virtual bool Load(const std::string& path) = 0;
    virtual void Unload() = 0;
    
    // Fast forward pass
    virtual std::vector<float> Forward(const std::vector<uint32_t>& tokens) = 0;
    
    // Batch forward
    virtual std::vector<std::vector<float>> ForwardBatch(
        const std::vector<std::vector<uint32_t>>& token_batches) = 0;
    
    // Sampling
    virtual uint32_t SampleToken(const std::vector<float>& logits,
                                  float temperature = 1.0f,
                                  uint32_t top_k = 50,
                                  float top_p = 0.9f) = 0;
    
    // Information
    virtual size_t GetParameterCount() const = 0;
    virtual size_t GetMemoryUsage() const = 0;
    virtual bool IsLoaded() const = 0;
};

// Utility functions for speculative decoding
namespace SpeculativeUtils {
    // Calculate acceptance probability
    float CalculateAcceptanceProbability(float draft_prob, float target_prob);
    
    // Modified rejection sampling
    uint32_t ModifiedRejectionSample(float draft_prob, float target_prob,
                                      const std::vector<float>& target_logits);
    
    // Adjust draft length based on acceptance rate
    uint32_t AdjustDraftLength(uint32_t current_length, float acceptance_rate,
                                float target_rate, uint32_t min_length, uint32_t max_length);
    
    // Validate speculative configuration
    bool ValidateConfig(const SpeculativeConfig& config);
    
    // Estimate memory requirements
    size_t EstimateMemoryRequirements(const SpeculativeConfig& config);
}

// Global speculative decoding configuration
extern SpeculativeConfig g_speculative_config;

// Initialize speculative decoding subsystem
bool InitializeSpeculativeDecoding(const SpeculativeConfig& config);
void ShutdownSpeculativeDecoding();
bool IsSpeculativeDecodingEnabled();

} // namespace Advanced
} // namespace RawrXD
