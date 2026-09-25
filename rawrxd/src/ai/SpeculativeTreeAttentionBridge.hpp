#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <optional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <queue>
#include <random>
#include <functional>
#include <algorithm>
#include <numeric>
#include <cstring>
#include <cmath>
#include <cassert>
#include <chrono>

namespace rawrxd::ai {

// ─── Forward Declarations ───
class InferenceSession;
class KVCacheManager;
class Tensor;
struct DraftModelConfig;
struct TreeAttentionConfig;

// ─── Tree Node Structure ───
// Each node represents a candidate token in the speculative tree.
// Children represent speculative continuations from this token.
struct SpeculativeTreeNode {
    int32_t token_id{ -1 };                 // Token index in vocab
    float logit{ 0.0f };                    // Raw logit from draft model
    float probability{ 0.0f };             // Draft model probability
    float cumulative_prob{ 0.0f };         // Cumulative probability along path
    float attention_score{ 0.0f };          // Cross-attention score (target↔draft)
    uint32_t depth{ 0 };                    // Depth in tree (0 = root)
    uint32_t parent_idx{ 0 };               // Index of parent node
    std::vector<uint32_t> child_indices;    // Indices of child nodes
    bool accepted{ false };                // Verification result
    bool verified{ false };                // Whether this node was scored by target
    std::vector<float> key_cache;          // Per-head K cache slice
    std::vector<float> value_cache;        // Per-head V cache slice
};

// ─── Draft Model Configuration ───
// Supports multiple draft models of varying sizes for ensemble speculation.
struct DraftModelConfig {
    std::string model_path;
    uint32_t num_layers{ 4 };
    uint32_t hidden_size{ 512 };
    uint32_t num_heads{ 8 };
    uint32_t head_dim{ 64 };
    uint32_t vocab_size{ 32000 };
    uint32_t max_seq_len{ 2048 };
    float temperature{ 1.0f };
    float top_p{ 0.9f };
    uint32_t top_k{ 50 };
    float repetition_penalty{ 1.0f };
    float draft_prob_threshold{ 0.6f };    // Minimum draft prob to consider
    float weight{ 1.0f };                  // Ensemble weight for this draft model
};

// ─── Tree Attention Configuration ───
struct TreeAttentionConfig {
    uint32_t max_tree_depth{ 8 };            // Maximum speculation depth
    uint32_t max_branching_factor{ 4 };      // Max children per node
    uint32_t max_tree_nodes{ 64 };          // Total nodes in speculative tree
    uint32_t num_draft_models{ 2 };           // Number of draft models to ensemble
    float acceptance_threshold{ 0.8f };     // Min probability for auto-accept
    float tree_attention_temperature{ 0.7f };
    bool use_kv_cache_optimization{ true };
    bool use_parallel_verification{ true };
    bool use_beam_search_pruning{ true };
    bool use_diversity_bonus{ true };
    float diversity_lambda{ 0.3f };         // Weight for diversity vs probability
    uint32_t verification_batch_size{ 32 }; // Batch size for target model verification
    uint32_t speculative_length_budget{ 16 }; // Max tokens to speculate ahead
    std::string cache_eviction_policy{ "lru" }; // lru | lfu | random
    uint64_t cache_size_bytes{ 8ULL * 1024 * 1024 * 1024 }; // 8GB default
};

// ─── Verification Result ───
struct TreeVerificationResult {
    std::vector<int32_t> accepted_tokens;
    std::vector<float> accepted_probs;
    std::vector<uint32_t> accepted_depths;
    uint32_t num_accepted{ 0 };
    uint32_t num_rejected{ 0 };
    uint32_t total_verified{ 0 };
    float acceptance_rate{ 0.0f };
    float mean_accepted_depth{ 0.0f };
    std::chrono::nanoseconds verification_time{ 0 };
    std::chrono::nanoseconds tree_construction_time{ 0 };
    std::chrono::nanoseconds total_round_time{ 0 };
};

// ─── Speculative Tree Attention Bridge ───
// Production-grade speculative decoding with tree-structured attention.
// Surpasses standard speculative decoding by accepting more tokens per forward pass
// through tree-based organization and cross-model attention scoring.
class SpeculativeTreeAttentionBridge {
public:
    explicit SpeculativeTreeAttentionBridge(const TreeAttentionConfig& config);
    ~SpeculativeTreeAttentionBridge();

    // Non-copyable, movable
    SpeculativeTreeAttentionBridge(const SpeculativeTreeAttentionBridge&) = delete;
    SpeculativeTreeAttentionBridge& operator=(const SpeculativeTreeAttentionBridge&) = delete;
    SpeculativeTreeAttentionBridge(SpeculativeTreeAttentionBridge&&) noexcept;
    SpeculativeTreeAttentionBridge& operator=(SpeculativeTreeAttentionBridge&&) noexcept;

    // ─── Core API ───

    // Initialize with draft model configurations
    bool Initialize(std::vector<DraftModelConfig> draft_configs,
                    std::shared_ptr<InferenceSession> target_session);

    // Perform one speculative decoding round
    // input_tokens: current context tokens
    // max_new_tokens: maximum tokens to generate this round
    // Returns accepted tokens from speculation
    std::vector<int32_t> SpeculateAndVerify(
        const std::vector<int32_t>& input_tokens,
        uint32_t max_new_tokens);

    // Batch speculation for multiple sequences (parallel)
    std::vector<std::vector<int32_t>> BatchSpeculateAndVerify(
        const std::vector<std::vector<int32_t>>& input_batches,
        uint32_t max_new_tokens_per_sequence);

    // ─── Tree Management ───

    // Build speculative tree from draft model predictions
    void BuildSpeculativeTree(
        const std::vector<int32_t>& prefix_tokens,
        uint32_t max_depth,
        uint32_t max_branching);

    // Prune tree using beam search with diversity bonus
    void PruneTreeWithDiversity(uint32_t max_nodes);

    // Compute attention scores between draft tree and target model
    void ComputeCrossAttentionScores();

    // ─── Verification ───

    // Verify tree nodes against target model in parallel batches
    TreeVerificationResult VerifyTreeNodes(
        const std::vector<int32_t>& prefix_tokens);

    // Adaptive verification: verify more promising paths first
    TreeVerificationResult VerifyTreeAdaptive(
        const std::vector<int32_t>& prefix_tokens);

    // ─── Statistics & Diagnostics ───

    TreeVerificationResult GetLastRoundStats() const { return last_result_; }
    float GetRollingAcceptanceRate() const;
    uint64_t GetTotalTokensGenerated() const { return total_tokens_generated_.load(); }
    uint64_t GetTotalTokensAccepted() const { return total_tokens_accepted_.load(); }
    float GetAverageTreeDepth() const;
    std::vector<float> GetPerDepthAcceptanceRates() const;

    // ─── KV Cache Management ───

    void EvictCache(const std::string& policy);
    void CompactCache();
    size_t GetCacheMemoryUsage() const;

    // ─── Configuration ───

    void UpdateConfig(const TreeAttentionConfig& new_config);
    TreeAttentionConfig GetConfig() const { return config_; }

    // ─── Debug & Export ───

    std::string ExportTreeDOT() const;
    void DumpTreeStatistics(std::ostream& out) const;

private:
    // ─── Internal Tree Operations ───

    void ExpandNode(uint32_t parent_idx, const std::vector<std::pair<int32_t, float>>& candidates);
    void ScoreNodeWithAttention(uint32_t node_idx);
    std::vector<uint32_t> SelectTopKNodes(uint32_t k) const;
    std::vector<uint32_t> GetPathToRoot(uint32_t node_idx) const;
    void BacktrackAndResample(uint32_t reject_idx);

    // ─── Draft Model Ensemble ───

    std::vector<std::pair<int32_t, float>> EnsembleDraftPredictions(
        const std::vector<int32_t>& context,
        uint32_t num_candidates);

    std::vector<std::pair<int32_t, float>> SingleDraftPredictions(
        uint32_t draft_idx,
        const std::vector<int32_t>& context,
        uint32_t num_candidates);

    // ─── Attention Computation ───

    void ComputeSelfAttentionForTree();
    void ComputeTreeTargetCrossAttention();
    float ComputeAttentionScore(const SpeculativeTreeNode& draft_node,
                                const std::vector<float>& target_query);

    // ─── Verification Internals ───

    std::vector<bool> BatchVerifyNodes(
        const std::vector<int32_t>& prefix,
        const std::vector<uint32_t>& node_indices);

    std::vector<float> GetTargetLogits(const std::vector<int32_t>& tokens);
    bool AcceptToken(int32_t draft_token, float draft_prob,
                     int32_t target_token, float target_prob);

    // ─── KV Cache ───

    void InitializeKVCache(uint32_t num_heads, uint32_t head_dim, uint32_t max_seq_len);
    void UpdateKVCache(uint32_t layer_idx, uint32_t seq_pos,
                       const std::vector<float>& key, const std::vector<float>& value);
    std::pair<std::vector<float>, std::vector<float>> RetrieveKVCache(
        uint32_t layer_idx, uint32_t seq_pos) const;

    // ─── Threading ───

    void StartWorkerThreads();
    void StopWorkerThreads();
    void WorkerLoop();

    // ─── Members ───

    TreeAttentionConfig config_;
    std::vector<DraftModelConfig> draft_configs_;
    std::shared_ptr<InferenceSession> target_session_;

    // Tree storage
    std::vector<SpeculativeTreeNode> tree_nodes_;
    uint32_t root_idx_{ 0 };
    uint32_t next_node_id_{ 1 };
    mutable std::mutex tree_mutex_;

    // KV Cache: [layer][seq_pos] -> (key, value)
    std::vector<std::vector<std::pair<std::vector<float>, std::vector<float>>>> kv_cache_;
    mutable std::mutex cache_mutex_;
    size_t cache_memory_used_{ 0 };

    // Statistics
    TreeVerificationResult last_result_;
    std::atomic<uint64_t> total_tokens_generated_{ 0 };
    std::atomic<uint64_t> total_tokens_accepted_{ 0 };
    std::vector<std::atomic<uint64_t>> depth_acceptance_counts_;
    std::vector<std::atomic<uint64_t>> depth_total_counts_;
    std::atomic<uint64_t> total_rounds_{ 0 };
    mutable std::mutex stats_mutex_;

    // Rolling statistics (exponential moving average)
    float rolling_acceptance_rate_{ 0.0f };
    static constexpr float ROLLING_ALPHA = 0.1f;

    // Threading
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> task_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::atomic<bool> shutdown_{ false };

    // Random
    std::mt19937 rng_{ std::random_device{}() };

    // Scratch buffers for attention computation
    std::vector<float> attention_scratch_;
    std::vector<float> softmax_scratch_;
    mutable std::mutex scratch_mutex_;
};

// ─── Free Functions ───

// Optimized softmax with numerical stability
inline void SoftmaxInPlace(std::vector<float>& logits) {
    if (logits.empty()) return;
    float max_logit = *std::max_element(logits.begin(), logits.end());
    float sum = 0.0f;
    for (auto& l : logits) {
        l = std::exp(l - max_logit);
        sum += l;
    }
    for (auto& l : logits) {
        l /= sum;
    }
}

// Top-k sampling with temperature
std::vector<std::pair<int32_t, float>> TopKSampling(
    const std::vector<float>& logits,
    uint32_t k,
    float temperature);

// Tree-structured attention kernel (SIMD-optimized)
void TreeAttentionKernel(
    const float* query,
    const float* keys,
    const float* values,
    const uint32_t* tree_indices,
    uint32_t num_nodes,
    uint32_t head_dim,
    float scale,
    float* output);

} // namespace rawrxd::ai
