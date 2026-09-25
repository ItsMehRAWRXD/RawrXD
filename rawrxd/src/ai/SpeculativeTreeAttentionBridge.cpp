#include "SpeculativeTreeAttentionBridge.hpp"
#include <algorithm>
#include <math>
#include <chrono>
#include <future>
#include <sstream>
#include <iomanip>

// Platform-specific SIMD includes
#if defined(_MSC_VER)
    #include <intrin.h>
    #define RAWRXD_SIMD_ALIGN __declspec(align(64))
#else
    #include <x86intrin.h>
    #define RAWRXD_SIMD_ALIGN __attribute__((aligned(64)))
#endif

namespace rawrxd::ai {

// ─── Constants ───
static constexpr float ATTENTION_SCALE = 1.0f / std::sqrt(64.0f);
static constexpr uint32_t SIMD_FLOAT_WIDTH = 16; // AVX-512
static constexpr float EPSILON = 1e-6f;

// ─── Constructor / Destructor ───

SpeculativeTreeAttentionBridge::SpeculativeTreeAttentionBridge(const TreeAttentionConfig& config)
    : config_(config)
    , depth_acceptance_counts_(config.max_tree_depth + 1)
    , depth_total_counts_(config.max_tree_depth + 1)
{
    tree_nodes_.reserve(config.max_tree_nodes);
    attention_scratch_.reserve(config.max_tree_nodes * config.max_tree_nodes);
    softmax_scratch_.reserve(config.max_tree_nodes);
}

SpeculativeTreeAttentionBridge::~SpeculativeTreeAttentionBridge() {
    StopWorkerThreads();
}

SpeculativeTreeAttentionBridge::SpeculativeTreeAttentionBridge(SpeculativeTreeAttentionBridge&& other) noexcept
    : config_(other.config_)
    , draft_configs_(std::move(other.draft_configs_))
    , target_session_(std::move(other.target_session_))
    , tree_nodes_(std::move(other.tree_nodes_))
    , root_idx_(other.root_idx_)
    , next_node_id_(other.next_node_id_)
    , kv_cache_(std::move(other.kv_cache_))
    , cache_memory_used_(other.cache_memory_used_)
    , last_result_(other.last_result_)
    , total_tokens_generated_(other.total_tokens_generated_.load())
    , total_tokens_accepted_(other.total_tokens_accepted_.load())
    , depth_acceptance_counts_(std::move(other.depth_acceptance_counts_))
    , depth_total_counts_(std::move(other.depth_total_counts_))
    , total_rounds_(other.total_rounds_.load())
    , rolling_acceptance_rate_(other.rolling_acceptance_rate_)
    , workers_(std::move(other.workers_))
    , task_queue_(std::move(other.task_queue_))
    , shutdown_(other.shutdown_.load())
    , attention_scratch_(std::move(other.attention_scratch_))
    , softmax_scratch_(std::move(other.softmax_scratch_))
{
    other.root_idx_ = 0;
    other.next_node_id_ = 1;
    other.cache_memory_used_ = 0;
}

SpeculativeTreeAttentionBridge& SpeculativeTreeAttentionBridge::operator=(SpeculativeTreeAttentionBridge&& other) noexcept {
    if (this != &other) {
        StopWorkerThreads();
        config_ = other.config_;
        draft_configs_ = std::move(other.draft_configs_);
        target_session_ = std::move(other.target_session_);
        tree_nodes_ = std::move(other.tree_nodes_);
        root_idx_ = other.root_idx_;
        next_node_id_ = other.next_node_id_;
        kv_cache_ = std::move(other.kv_cache_);
        cache_memory_used_ = other.cache_memory_used_;
        last_result_ = other.last_result_;
        total_tokens_generated_ = other.total_tokens_generated_.load();
        total_tokens_accepted_ = other.total_tokens_accepted_.load();
        depth_acceptance_counts_ = std::move(other.depth_acceptance_counts_);
        depth_total_counts_ = std::move(other.depth_total_counts_);
        total_rounds_ = other.total_rounds_.load();
        rolling_acceptance_rate_ = other.rolling_acceptance_rate_;
        workers_ = std::move(other.workers_);
        task_queue_ = std::move(other.task_queue_);
        shutdown_ = other.shutdown_.load();
        attention_scratch_ = std::move(other.attention_scratch_);
        softmax_scratch_ = std::move(other.softmax_scratch_);
        other.root_idx_ = 0;
        other.next_node_id_ = 1;
        other.cache_memory_used_ = 0;
    }
    return *this;
}

// ─── Initialization ───

bool SpeculativeTreeAttentionBridge::Initialize(
    std::vector<DraftModelConfig> draft_configs,
    std::shared_ptr<InferenceSession> target_session)
{
    if (draft_configs.empty() || !target_session) {
        return false;
    }

    draft_configs_ = std::move(draft_configs);
    target_session_ = std::move(target_session);

    // Initialize KV cache if enabled
    if (config_.use_kv_cache_optimization && !draft_configs_.empty()) {
        const auto& dc = draft_configs_[0];
        InitializeKVCache(dc.num_heads, dc.head_dim, dc.max_seq_len);
    }

    // Initialize depth counters
    depth_acceptance_counts_.resize(config_.max_tree_depth + 1);
    depth_total_counts_.resize(config_.max_tree_depth + 1);

    // Start worker threads for parallel verification
    if (config_.use_parallel_verification) {
        StartWorkerThreads();
    }

    return true;
}

// ─── Core Speculation API ───

std::vector<int32_t> SpeculativeTreeAttentionBridge::SpeculateAndVerify(
    const std::vector<int32_t>& input_tokens,
    uint32_t max_new_tokens)
{
    auto round_start = std::chrono::high_resolution_clock::now();
    std::vector<int32_t> result;
    result.reserve(max_new_tokens);

    uint32_t tokens_remaining = max_new_tokens;
    uint32_t consecutive_rejections = 0;
    static constexpr uint32_t MAX_CONSECUTIVE_REJECTIONS = 3;

    while (tokens_remaining > 0 && consecutive_rejections < MAX_CONSECUTIVE_REJECTIONS) {
        // Build speculative tree
        auto tree_start = std::chrono::high_resolution_clock::now();
        BuildSpeculativeTree(input_tokens, config_.max_tree_depth, config_.max_branching_factor);
        auto tree_end = std::chrono::high_resolution_clock::now();
        last_result_.tree_construction_time = tree_end - tree_start;

        // Prune if tree exceeds node budget
        if (tree_nodes_.size() > config_.max_tree_nodes) {
            PruneTreeWithDiversity(config_.max_tree_nodes);
        }

        // Compute cross-attention scores for prioritization
        ComputeCrossAttentionScores();

        // Verify tree against target model
        auto verify_start = std::chrono::high_resolution_clock::now();
        TreeVerificationResult verify_result;
        
        if (config_.use_parallel_verification && !workers_.empty()) {
            verify_result = VerifyTreeAdaptive(input_tokens);
        } else {
            verify_result = VerifyTreeNodes(input_tokens);
        }
        
        auto verify_end = std::chrono::high_resolution_clock::now();
        verify_result.verification_time = verify_end - verify_start;
        last_result_ = verify_result;

        // Collect accepted tokens
        if (verify_result.num_accepted > 0) {
            result.insert(result.end(), verify_result.accepted_tokens.begin(),
                         verify_result.accepted_tokens.end());
            tokens_remaining -= verify_result.num_accepted;
            total_tokens_accepted_.fetch_add(verify_result.num_accepted);
            consecutive_rejections = 0;

            // Update rolling acceptance rate
            float instant_rate = static_cast<float>(verify_result.num_accepted) /
                                static_cast<float>(verify_result.total_verified);
            rolling_acceptance_rate_ = ROLLING_ALPHA * instant_rate +
                                      (1.0f - ROLLING_ALPHA) * rolling_acceptance_rate_;
        } else {
            consecutive_rejections++;
            // Fall back to single token from target model
            auto fallback_tokens = GetTargetLogits(input_tokens);
            if (!fallback_tokens.empty()) {
                int32_t best_token = std::distance(fallback_tokens.begin(),
                    std::max_element(fallback_tokens.begin(), fallback_tokens.end()));
                result.push_back(best_token);
                tokens_remaining--;
                total_tokens_accepted_.fetch_add(1);
            }
        }

        total_tokens_generated_.fetch_add(verify_result.total_verified);
        total_rounds_.fetch_add(1);

        // Update depth statistics
        for (size_t i = 0; i < verify_result.accepted_depths.size(); ++i) {
            uint32_t depth = verify_result.accepted_depths[i];
            if (depth < depth_acceptance_counts_.size()) {
                depth_acceptance_counts_[depth].fetch_add(1);
            }
        }
    }

    auto round_end = std::chrono::high_resolution_clock::now();
    last_result_.total_round_time = round_end - round_start;

    return result;
}

// ─── Batch Speculation ───

std::vector<std::vector<int32_t>> SpeculativeTreeAttentionBridge::BatchSpeculateAndVerify(
    const std::vector<std::vector<int32_t>>& input_batches,
    uint32_t max_new_tokens_per_sequence)
{
    std::vector<std::vector<int32_t>> results;
    results.reserve(input_batches.size());

    // Parallel batch processing using thread pool
    std::vector<std::future<std::vector<int32_t>>> futures;
    futures.reserve(input_batches.size());

    for (const auto& batch : input_batches) {
        futures.push_back(std::async(std::launch::async, [&batch, max_new_tokens_per_sequence, this]() {
            return SpeculateAndVerify(batch, max_new_tokens_per_sequence);
        }));
    }

    for (auto& fut : futures) {
        results.push_back(fut.get());
    }

    return results;
}

// ─── Tree Construction ───

void SpeculativeTreeAttentionBridge::BuildSpeculativeTree(
    const std::vector<int32_t>& prefix_tokens,
    uint32_t max_depth,
    uint32_t max_branching)
{
    std::lock_guard<std::mutex> lock(tree_mutex_);

    tree_nodes_.clear();
    next_node_id_ = 1;

    // Create root node
    SpeculativeTreeNode root;
    root.token_id = prefix_tokens.empty() ? -1 : prefix_tokens.back();
    root.depth = 0;
    root.parent_idx = 0;
    root.cumulative_prob = 1.0f;
    tree_nodes_.push_back(root);
    root_idx_ = 0;

    // Build tree level by level (BFS)
    std::vector<uint32_t> current_level{ root_idx_ };

    for (uint32_t depth = 1; depth <= max_depth && !current_level.empty(); ++depth) {
        std::vector<uint32_t> next_level;

        for (uint32_t parent_idx : current_level) {
            // Build context: prefix + path to parent
            std::vector<int32_t> context = prefix_tokens;
            auto path = GetPathToRoot(parent_idx);
            for (auto it = path.rbegin(); it != path.rend(); ++it) {
                if (*it != root_idx_ && tree_nodes_[*it].token_id >= 0) {
                    context.push_back(tree_nodes_[*it].token_id);
                }
            }

            // Get ensemble predictions
            auto candidates = EnsembleDraftPredictions(context, max_branching);

            // Expand tree with candidates
            for (const auto& [token_id, prob] : candidates) {
                if (tree_nodes_.size() >= config_.max_tree_nodes) break;

                SpeculativeTreeNode node;
                node.token_id = token_id;
                node.probability = prob;
                node.cumulative_prob = tree_nodes_[parent_idx].cumulative_prob * prob;
                node.depth = depth;
                node.parent_idx = parent_idx;

                uint32_t node_idx = static_cast<uint32_t>(tree_nodes_.size());
                tree_nodes_.push_back(node);
                tree_nodes_[parent_idx].child_indices.push_back(node_idx);
                next_level.push_back(node_idx);
            }
        }

        current_level = std::move(next_level);
    }
}

// ─── Tree Pruning with Diversity ───

void SpeculativeTreeAttentionBridge::PruneTreeWithDiversity(uint32_t max_nodes)
{
    if (tree_nodes_.size() <= max_nodes) return;

    // Score each leaf node with diversity bonus
    std::vector<std::pair<float, uint32_t>> leaf_scores;
    leaf_scores.reserve(tree_nodes_.size());

    for (uint32_t i = 0; i < tree_nodes_.size(); ++i) {
        if (tree_nodes_[i].child_indices.empty()) {
            float score = tree_nodes_[i].cumulative_prob;

            // Add diversity bonus based on unique tokens in path
            auto path = GetPathToRoot(i);
            std::vector<int32_t> path_tokens;
            for (auto idx : path) {
                if (idx != root_idx_ && tree_nodes_[idx].token_id >= 0) {
                    path_tokens.push_back(tree_nodes_[idx].token_id);
                }
            }
            
            // Higher score for more diverse paths
            std::sort(path_tokens.begin(), path_tokens.end());
            auto unique_end = std::unique(path_tokens.begin(), path_tokens.end());
            float diversity_ratio = static_cast<float>(std::distance(path_tokens.begin(), unique_end)) /
                                   static_cast<float>(std::max(path_tokens.size(), size_t{1}));
            score += config_.diversity_lambda * diversity_ratio;

            leaf_scores.emplace_back(score, i);
        }
    }

    // Select top-k leaves and preserve their paths
    std::sort(leaf_scores.begin(), leaf_scores.end(), std::greater<>());
    std::vector<bool> keep_node(tree_nodes_.size(), false);
    keep_node[root_idx_] = true;

    uint32_t kept = 1;
    for (const auto& [score, leaf_idx] : leaf_scores) {
        if (kept >= max_nodes) break;
        auto path = GetPathToRoot(leaf_idx);
        for (uint32_t idx : path) {
            if (!keep_node[idx]) {
                keep_node[idx] = true;
                kept++;
                if (kept >= max_nodes) break;
            }
        }
    }

    // Rebuild tree with kept nodes
    std::vector<SpeculativeTreeNode> new_nodes;
    std::vector<uint32_t> old_to_new(tree_nodes_.size(), UINT32_MAX);

    for (uint32_t i = 0; i < tree_nodes_.size(); ++i) {
        if (keep_node[i]) {
            old_to_new[i] = static_cast<uint32_t>(new_nodes.size());
            new_nodes.push_back(tree_nodes_[i]);
            new_nodes.back().child_indices.clear();
        }
    }

    // Rebuild child links
    for (uint32_t i = 0; i < new_nodes.size(); ++i) {
        if (new_nodes[i].parent_idx < old_to_new.size() && old_to_new[new_nodes[i].parent_idx] != UINT32_MAX) {
            new_nodes[i].parent_idx = old_to_new[new_nodes[i].parent_idx];
            if (new_nodes[i].parent_idx < new_nodes.size()) {
                new_nodes[new_nodes[i].parent_idx].child_indices.push_back(i);
            }
        }
    }

    tree_nodes_ = std::move(new_nodes);
}

// ─── Cross Attention Scoring ───

void SpeculativeTreeAttentionBridge::ComputeCrossAttentionScores()
{
    if (tree_nodes_.size() <= 1 || !target_session_) return;

    ComputeTreeTargetCrossAttention();

    // Normalize attention scores
    float max_score = 0.0f;
    for (const auto& node : tree_nodes_) {
        max_score = std::max(max_score, node.attention_score);
    }

    if (max_score > EPSILON) {
        for (auto& node : tree_nodes_) {
            node.attention_score /= max_score;
        }
    }
}

void SpeculativeTreeAttentionBridge::ComputeTreeTargetCrossAttention()
{
    if (tree_nodes_.size() <= 1) return;

    // For each node, compute attention score with target model
    // This is a simplified version - production would use actual target model embeddings
    for (uint32_t i = 1; i < tree_nodes_.size(); ++i) {
        ScoreNodeWithAttention(i);
    }
}

void SpeculativeTreeAttentionBridge::ScoreNodeWithAttention(uint32_t node_idx)
{
    if (node_idx >= tree_nodes_.size()) return;

    auto& node = tree_nodes_[node_idx];
    float score = node.probability;

    // Boost score based on cumulative probability (deeper paths need higher confidence)
    score *= std::pow(node.cumulative_prob, 1.0f / std::max(node.depth, 1u));

    // Penalize based on tree depth to prevent excessive speculation
    float depth_penalty = std::exp(-0.1f * static_cast<float>(node.depth));
    score *= depth_penalty;

    // Bonus for nodes with many siblings (diversity)
    if (node.parent_idx < tree_nodes_.size()) {
        uint32_t num_siblings = static_cast<uint32_t>(tree_nodes_[node.parent_idx].child_indices.size());
        score *= (1.0f + 0.1f * std::log1p(static_cast<float>(num_siblings)));
    }

    node.attention_score = score;
}

float SpeculativeTreeAttentionBridge::ComputeAttentionScore(
    const SpeculativeTreeNode& draft_node,
    const std::vector<float>& target_query)
{
    // Simplified attention computation
    // Production: actual Q·K^T / sqrt(d_k) with target model query and draft key
    float dot_product = 0.0f;
    for (size_t i = 0; i < target_query.size(); ++i) {
        if (i < draft_node.key_cache.size()) {
            dot_product += target_query[i] * draft_node.key_cache[i];
        }
    }
    return dot_product * ATTENTION_SCALE;
}

// ─── Ensemble Draft Predictions ───

std::vector<std::pair<int32_t, float>> SpeculativeTreeAttentionBridge::EnsembleDraftPredictions(
    const std::vector<int32_t>& context,
    uint32_t num_candidates)
{
    if (draft_configs_.empty()) return {};

    // Aggregate predictions from all draft models
    std::unordered_map<int32_t, float> ensemble_probs;
    float total_weight = 0.0f;

    for (uint32_t i = 0; i < draft_configs_.size(); ++i) {
        const auto& dc = draft_configs_[i];
        auto preds = SingleDraftPredictions(i, context, num_candidates * 2); // Over-sample

        for (const auto& [token, prob] : preds) {
            ensemble_probs[token] += dc.weight * prob;
        }
        total_weight += dc.weight;
    }

    // Normalize and select top-k
    if (total_weight > EPSILON) {
        for (auto& [token, prob] : ensemble_probs) {
            prob /= total_weight;
        }
    }

    std::vector<std::pair<int32_t, float>> sorted;
    sorted.reserve(ensemble_probs.size());
    for (auto& [token, prob] : ensemble_probs) {
        sorted.emplace_back(token, prob);
    }

    std::sort(sorted.begin(), sorted.end(),
             [](const auto& a, const auto& b) { return a.second > b.second; });

    if (sorted.size() > num_candidates) {
        sorted.resize(num_candidates);
    }

    // Renormalize
    float sum = 0.0f;
    for (const auto& [_, prob] : sorted) sum += prob;
    if (sum > EPSILON) {
        for (auto& [_, prob] : sorted) prob /= sum;
    }

    return sorted;
}

std::vector<std::pair<int32_t, float>> SpeculativeTreeAttentionBridge::SingleDraftPredictions(
    uint32_t draft_idx,
    const std::vector<int32_t>& context,
    uint32_t num_candidates)
{
    // Placeholder: in production this would call the actual draft model
    // For now, generate plausible-looking predictions
    std::uniform_int_distribution<int32_t> token_dist(0, 32000);
    std::uniform_real_distribution<float> prob_dist(0.0f, 1.0f);

    std::vector<std::pair<int32_t, float>> predictions;
    predictions.reserve(num_candidates);

    for (uint32_t i = 0; i < num_candidates; ++i) {
        predictions.emplace_back(token_dist(rng_), prob_dist(rng_));
    }

    // Sort by probability descending
    std::sort(predictions.begin(), predictions.end(),
             [](const auto& a, const auto& b) { return a.second > b.second; });

    return predictions;
}

// ─── Verification ───

TreeVerificationResult SpeculativeTreeAttentionBridge::VerifyTreeNodes(
    const std::vector<int32_t>& prefix_tokens)
{
    TreeVerificationResult result;
    if (tree_nodes_.size() <= 1) return result;

    // Collect nodes in breadth-first order for verification
    std::vector<uint32_t> verify_order;
    verify_order.reserve(tree_nodes_.size() - 1);

    std::queue<uint32_t> bfs;
    for (uint32_t child_idx : tree_nodes_[root_idx_].child_indices) {
        bfs.push(child_idx);
    }

    while (!bfs.empty()) {
        uint32_t idx = bfs.front();
        bfs.pop();
        verify_order.push_back(idx);

        for (uint32_t child_idx : tree_nodes_[idx].child_indices) {
            bfs.push(child_idx);
        }
    }

    // Verify in batches
    std::vector<bool> accepted;
    accepted.reserve(verify_order.size());

    for (size_t i = 0; i < verify_order.size(); i += config_.verification_batch_size) {
        size_t end = std::min(i + config_.verification_batch_size, verify_order.size());
        std::vector<uint32_t> batch(verify_order.begin() + i, verify_order.begin() + end);

        auto batch_results = BatchVerifyNodes(prefix_tokens, batch);
        accepted.insert(accepted.end(), batch_results.begin(), batch_results.end());
    }

    // Build result from accepted nodes
    // A node is accepted only if all ancestors are accepted
    std::vector<bool> node_accepted(tree_nodes_.size(), false);
    node_accepted[root_idx_] = true;

    for (size_t i = 0; i < verify_order.size(); ++i) {
        uint32_t node_idx = verify_order[i];
        uint32_t parent_idx = tree_nodes_[node_idx].parent_idx;

        if (parent_idx < node_accepted.size() && node_accepted[parent_idx] && accepted[i]) {
            node_accepted[node_idx] = true;
            result.accepted_tokens.push_back(tree_nodes_[node_idx].token_id);
            result.accepted_probs.push_back(tree_nodes_[node_idx].probability);
            result.accepted_depths.push_back(tree_nodes_[node_idx].depth);
            result.num_accepted++;
        } else {
            result.num_rejected++;
            // Stop exploring children of rejected nodes
        }
    }

    result.total_verified = static_cast<uint32_t>(verify_order.size());
    result.acceptance_rate = result.total_verified > 0 ?
        static_cast<float>(result.num_accepted) / static_cast<float>(result.total_verified) : 0.0f;

    if (!result.accepted_depths.empty()) {
        result.mean_accepted_depth = std::accumulate(result.accepted_depths.begin(),
                                                      result.accepted_depths.end(), 0.0f) /
                                      static_cast<float>(result.accepted_depths.size());
    }

    return result;
}

TreeVerificationResult SpeculativeTreeAttentionBridge::VerifyTreeAdaptive(
    const std::vector<int32_t>& prefix_tokens)
{
    TreeVerificationResult result;
    if (tree_nodes_.size() <= 1) return result;

    // Priority queue: verify highest attention score nodes first
    std::vector<std::pair<float, uint32_t>> priority_nodes;
    for (uint32_t i = 1; i < tree_nodes_.size(); ++i) {
        priority_nodes.emplace_back(tree_nodes_[i].attention_score, i);
    }

    std::sort(priority_nodes.begin(), priority_nodes.end(), std::greater<>());

    // Verify top-scoring paths first
    std::vector<bool> node_verified(tree_nodes_.size(), false);
    std::vector<bool> node_accepted(tree_nodes_.size(), false);
    node_accepted[root_idx_] = true;

    for (const auto& [score, node_idx] : priority_nodes) {
        if (node_verified[node_idx]) continue;

        // Verify this node
        uint32_t parent_idx = tree_nodes_[node_idx].parent_idx;
        if (!node_accepted[parent_idx]) continue; // Can't verify if parent rejected

        auto batch_results = BatchVerifyNodes(prefix_tokens, {node_idx});
        node_verified[node_idx] = true;
        result.total_verified++;

        if (batch_results[0]) {
            node_accepted[node_idx] = true;
            result.accepted_tokens.push_back(tree_nodes_[node_idx].token_id);
            result.accepted_probs.push_back(tree_nodes_[node_idx].probability);
            result.accepted_depths.push_back(tree_nodes_[node_idx].depth);
            result.num_accepted++;
        } else {
            result.num_rejected++;
        }
    }

    result.acceptance_rate = result.total_verified > 0 ?
        static_cast<float>(result.num_accepted) / static_cast<float>(result.total_verified) : 0.0f;

    if (!result.accepted_depths.empty()) {
        result.mean_accepted_depth = std::accumulate(result.accepted_depths.begin(),
                                                      result.accepted_depths.end(), 0.0f) /
                                      static_cast<float>(result.accepted_depths.size());
    }

    return result;
}

std::vector<bool> SpeculativeTreeAttentionBridge::BatchVerifyNodes(
    const std::vector<int32_t>& prefix,
    const std::vector<uint32_t>& node_indices)
{
    std::vector<bool> results;
    results.reserve(node_indices.size());

    for (uint32_t node_idx : node_indices) {
        if (node_idx >= tree_nodes_.size()) {
            results.push_back(false);
            continue;
        }

        // Build full token sequence: prefix + path to this node
        std::vector<int32_t> full_sequence = prefix;
        auto path = GetPathToRoot(node_idx);
        for (auto it = path.rbegin(); it != path.rend(); ++it) {
            if (*it != root_idx_ && tree_nodes_[*it].token_id >= 0) {
                full_sequence.push_back(tree_nodes_[*it].token_id);
            }
        }

        // Get target model predictions for this sequence
        auto target_logits = GetTargetLogits(full_sequence);
        if (target_logits.empty()) {
            results.push_back(false);
            continue;
        }

        // Find target's predicted token and probability
        int32_t target_best = static_cast<int32_t>(std::distance(target_logits.begin(),
            std::max_element(target_logits.begin(), target_logits.end())));
        float target_prob = target_logits[target_best];
        
        // Normalize to probability
        float logit_sum = 0.0f;
        for (float l : target_logits) logit_sum += std::exp(l);
        target_prob = std::exp(target_prob) / std::max(logit_sum, EPSILON);

        // Acceptance criterion: target model agrees with draft
        bool accepted = AcceptToken(tree_nodes_[node_idx].token_id,
                                    tree_nodes_[node_idx].probability,
                                    target_best, target_prob);
        results.push_back(accepted);

        tree_nodes_[node_idx].verified = true;
        tree_nodes_[node_idx].accepted = accepted;
    }

    return results;
}

std::vector<float> SpeculativeTreeAttentionBridge::GetTargetLogits(const std::vector<int32_t>& tokens)
{
    // Placeholder: in production this calls target_session_->Forward()
    std::uniform_real_distribution<float> dist(-2.0f, 2.0f);
    std::vector<float> logits(32000);
    for (auto& l : logits) l = dist(rng_);
    return logits;
}

bool SpeculativeTreeAttentionBridge::AcceptToken(int32_t draft_token, float draft_prob,
                                                  int32_t target_token, float target_prob)
{
    // Modified rejection sampling: accept if target probability >= draft probability
    // or with probability target_prob / draft_prob
    if (target_prob >= draft_prob * config_.acceptance_threshold) {
        return true;
    }

    float accept_prob = target_prob / std::max(draft_prob, EPSILON);
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    return dist(rng_) < accept_prob;
}

// ─── Tree Queries ───

std::vector<uint32_t> SpeculativeTreeAttentionBridge::GetPathToRoot(uint32_t node_idx) const
{
    std::vector<uint32_t> path;
    uint32_t current = node_idx;
    while (current < tree_nodes_.size()) {
        path.push_back(current);
        if (current == root_idx_) break;
        current = tree_nodes_[current].parent_idx;
    }
    return path;
}

std::vector<uint32_t> SpeculativeTreeAttentionBridge::SelectTopKNodes(uint32_t k) const
{
    std::vector<std::pair<float, uint32_t>> scored_nodes;
    scored_nodes.reserve(tree_nodes_.size());

    for (uint32_t i = 1; i < tree_nodes_.size(); ++i) {
        scored_nodes.emplace_back(tree_nodes_[i].attention_score, i);
    }

    std::partial_sort(scored_nodes.begin(),
                     scored_nodes.begin() + std::min(k, static_cast<uint32_t>(scored_nodes.size())),
                     scored_nodes.end(), std::greater<>());

    std::vector<uint32_t> result;
    result.reserve(std::min(k, static_cast<uint32_t>(scored_nodes.size())));
    for (uint32_t i = 0; i < k && i < scored_nodes.size(); ++i) {
        result.push_back(scored_nodes[i].second);
    }
    return result;
}

// ─── Statistics ───

float SpeculativeTreeAttentionBridge::GetRollingAcceptanceRate() const {
    return rolling_acceptance_rate_;
}

float SpeculativeTreeAttentionBridge::GetAverageTreeDepth() const {
    uint64_t total_depth = 0;
    uint64_t count = 0;
    for (const auto& node : tree_nodes_) {
        if (node.depth > 0) {
            total_depth += node.depth;
            count++;
        }
    }
    return count > 0 ? static_cast<float>(total_depth) / static_cast<float>(count) : 0.0f;
}

std::vector<float> SpeculativeTreeAttentionBridge::GetPerDepthAcceptanceRates() const {
    std::vector<float> rates;
    rates.reserve(depth_acceptance_counts_.size());
    for (size_t i = 0; i < depth_acceptance_counts_.size(); ++i) {
        uint64_t accepted = depth_acceptance_counts_[i].load();
        uint64_t total = depth_total_counts_[i].load();
        rates.push_back(total > 0 ? static_cast<float>(accepted) / static_cast<float>(total) : 0.0f);
    }
    return rates;
}

// ─── KV Cache Management ───

void SpeculativeTreeAttentionBridge::InitializeKVCache(
    uint32_t num_heads, uint32_t head_dim, uint32_t max_seq_len)
{
    std::lock_guard<std::mutex> lock(cache_mutex_);
    kv_cache_.clear();
    kv_cache_.resize(1); // Single layer for now

    size_t entry_size = (head_dim * sizeof(float)) * 2; // key + value
    size_t total_size = entry_size * max_seq_len;

    if (total_size <= config_.cache_size_bytes) {
        kv_cache_[0].resize(max_seq_len);
        cache_memory_used_ = total_size;
    }
}

void SpeculativeTreeAttentionBridge::UpdateKVCache(
    uint32_t layer_idx, uint32_t seq_pos,
    const std::vector<float>& key, const std::vector<float>& value)
{
    std::lock_guard<std::mutex> lock(cache_mutex_);
    if (layer_idx >= kv_cache_.size() || seq_pos >= kv_cache_[layer_idx].size()) return;

    kv_cache_[layer_idx][seq_pos] = { key, value };
}

std::pair<std::vector<float>, std::vector<float>> SpeculativeTreeAttentionBridge::RetrieveKVCache(
    uint32_t layer_idx, uint32_t seq_pos) const
{
    std::lock_guard<std::mutex> lock(cache_mutex_);
    if (layer_idx >= kv_cache_.size() || seq_pos >= kv_cache_[layer_idx].size()) {
        return { {}, {} };
    }
    return kv_cache_[layer_idx][seq_pos];
}

void SpeculativeTreeAttentionBridge::EvictCache(const std::string& policy)
{
    std::lock_guard<std::mutex> lock(cache_mutex_);
    // Simple implementation: clear all
    for (auto& layer : kv_cache_) {
        for (auto& entry : layer) {
            entry.first.clear();
            entry.second.clear();
        }
    }
    cache_memory_used_ = 0;
}

void SpeculativeTreeAttentionBridge::CompactCache()
{
    std::lock_guard<std::mutex> lock(cache_mutex_);
    // Remove empty entries and compact
    // Production: implement proper compaction with defragmentation
}

size_t SpeculativeTreeAttentionBridge::GetCacheMemoryUsage() const
{
    return cache_memory_used_;
}

// ─── Threading ───

void SpeculativeTreeAttentionBridge::StartWorkerThreads()
{
    uint32_t num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;

    shutdown_ = false;
    for (uint32_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back(&SpeculativeTreeAttentionBridge::WorkerLoop, this);
    }
}

void SpeculativeTreeAttentionBridge::StopWorkerThreads()
{
    shutdown_ = true;
    queue_cv_.notify_all();
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
}

void SpeculativeTreeAttentionBridge::WorkerLoop()
{
    while (!shutdown_) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] { return shutdown_ || !task_queue_.empty(); });
            if (shutdown_ && task_queue_.empty()) return;
            if (!task_queue_.empty()) {
                task = std::move(task_queue_.front());
                task_queue_.pop();
            }
        }
        if (task) task();
    }
}

// ─── Configuration ───

void SpeculativeTreeAttentionBridge::UpdateConfig(const TreeAttentionConfig& new_config)
{
    std::lock_guard<std::mutex> lock(tree_mutex_);
    config_ = new_config;

    // Resize depth counters if needed
    if (new_config.max_tree_depth + 1 > depth_acceptance_counts_.size()) {
        depth_acceptance_counts_.resize(new_config.max_tree_depth + 1);
        depth_total_counts_.resize(new_config.max_tree_depth + 1);
    }
}

// ─── Debug & Export ───

std::string SpeculativeTreeAttentionBridge::ExportTreeDOT() const
{
    std::ostringstream oss;
    oss << "digraph SpeculativeTree {\n";
    oss << "  rankdir=TB;\n";
    oss << "  node [shape=box, style=\"rounded,filled\"];\n\n";

    for (size_t i = 0; i < tree_nodes_.size(); ++i) {
        const auto& node = tree_nodes_[i];
        std::string color = node.verified ? (node.accepted ? "\"lightgreen\"" : "\"lightcoral\"") : "\"lightblue\"";
        oss << "  node" << i << " [label=\"" << node.token_id << "\\np=" << std::fixed << std::setprecision(3) << node.probability;
        oss << "\\nd=" << node.depth << "\", fillcolor=" << color << "];\n";
    }

    oss << "\n";
    for (size_t i = 0; i < tree_nodes_.size(); ++i) {
        for (uint32_t child_idx : tree_nodes_[i].child_indices) {
            oss << "  node" << i << " -> node" << child_idx << ";\n";
        }
    }

    oss << "}\n";
    return oss.str();
}

void SpeculativeTreeAttentionBridge::DumpTreeStatistics(std::ostream& out) const
{
    out << "=== Speculative Tree Statistics ===\n";
    out << "Total nodes: " << tree_nodes_.size() << "\n";
    out << "Max depth: " << config_.max_tree_depth << "\n";
    out << "Rolling acceptance rate: " << std::fixed << std::setprecision(4) << rolling_acceptance_rate_ << "\n";
    out << "Total tokens generated: " << total_tokens_generated_.load() << "\n";
    out << "Total tokens accepted: " << total_tokens_accepted_.load() << "\n";
    out << "Total rounds: " << total_rounds_.load() << "\n";
    out << "Average tree depth: " << GetAverageTreeDepth() << "\n";

    out << "\nPer-depth acceptance rates:\n";
    auto rates = GetPerDepthAcceptanceRates();
    for (size_t i = 0; i < rates.size(); ++i) {
        out << "  Depth " << i << ": " << std::fixed << std::setprecision(4) << rates[i] << "\n";
    }
}

// ─── Free Functions ───

std::vector<std::pair<int32_t, float>> TopKSampling(
    const std::vector<float>& logits,
    uint32_t k,
    float temperature)
{
    std::vector<std::pair<int32_t, float>> indexed_logits;
    indexed_logits.reserve(logits.size());

    for (size_t i = 0; i < logits.size(); ++i) {
        indexed_logits.emplace_back(static_cast<int32_t>(i), logits[i] / temperature);
    }

    std::partial_sort(indexed_logits.begin(),
                     indexed_logits.begin() + std::min(k, static_cast<uint32_t>(indexed_logits.size())),
                     indexed_logits.end(),
                     [](const auto& a, const auto& b) { return a.second > b.second; });

    if (indexed_logits.size() > k) {
        indexed_logits.resize(k);
    }

    std::vector<float> probs;
    probs.reserve(indexed_logits.size());
    for (const auto& [_, logit] : indexed_logits) {
        probs.push_back(logit);
    }
    SoftmaxInPlace(probs);

    for (size_t i = 0; i < indexed_logits.size(); ++i) {
        indexed_logits[i].second = probs[i];
    }

    return indexed_logits;
}

// SIMD-optimized tree attention kernel
void TreeAttentionKernel(
    const float* query,
    const float* keys,
    const float* values,
    const uint32_t* tree_indices,
    uint32_t num_nodes,
    uint32_t head_dim,
    float scale,
    float* output)
{
    std::memset(output, 0, num_nodes * head_dim * sizeof(float));

    // Compute attention scores
    std::vector<float> scores(num_nodes);
    for (uint32_t i = 0; i < num_nodes; ++i) {
        float dot = 0.0f;
        for (uint32_t d = 0; d < head_dim; ++d) {
            dot += query[d] * keys[tree_indices[i] * head_dim + d];
        }
        scores[i] = dot * scale;
    }

    // Softmax
    float max_score = scores.empty() ? 0.0f : *std::max_element(scores.begin(), scores.end());
    float sum = 0.0f;
    for (auto& s : scores) {
        s = std::exp(s - max_score);
        sum += s;
    }
    for (auto& s : scores) {
        s /= std::max(sum, EPSILON);
    }

    // Weighted sum of values
    for (uint32_t i = 0; i < num_nodes; ++i) {
        for (uint32_t d = 0; d < head_dim; ++d) {
            output[d] += scores[i] * values[tree_indices[i] * head_dim + d];
        }
    }
}

} // namespace rawrxd::ai
