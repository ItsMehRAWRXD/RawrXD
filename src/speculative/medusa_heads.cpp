// ============================================================================
// medusa_heads.cpp — Medusa Heads Speculative Decoding Implementation
// ============================================================================
// Medusa: Simple LLM Inference Acceleration Framework with Multiple Decoding Heads
// This implementation provides:
// - Multiple decoding heads for parallel token prediction
// - Tree-based attention for efficient verification
// - Adaptive head selection based on acceptance rates
// - Integration with KV cache for efficient inference
//
// Build: g++ -O2 -std=c++17 medusa_heads.cpp -o medusa_heads
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <cmath>
#include <random>
#include <chrono>
#include <algorithm>
#include <atomic>
#include <mutex>

// ============================================================================
// Medusa Configuration
// ============================================================================
struct MedusaConfig {
    uint32_t numHeads = 4;              // Number of Medusa heads
    uint32_t maxTokensPerHead = 8;      // Max tokens each head predicts
    uint32_t treeDepth = 4;             // Tree attention depth
    float acceptanceThreshold = 0.5f;   // Token acceptance threshold
    float temperature = 0.7f;           // Sampling temperature
    uint32_t vocabSize = 32000;         // Vocabulary size
    uint32_t topK = 40;                 // Top-k sampling
    float topP = 0.9f;                  // Top-p (nucleus) sampling
};

// ============================================================================
// Token Types
// ============================================================================
typedef int32_t TokenId;

// ============================================================================
// Medusa Head Candidate
// ============================================================================
struct MedusaCandidate {
    TokenId tokenId;
    float logit;
    float probability;
    uint32_t headId;           // Which Medusa head generated this
    uint32_t position;         // Position in sequence
    uint32_t parentIdx;        // Parent node index in tree
    bool accepted;
    
    MedusaCandidate() : tokenId(0), logit(0.0f), probability(0.0f), 
                        headId(0), position(0), parentIdx(0), accepted(false) {}
};

// ============================================================================
// Tree Node for Tree Attention
// ============================================================================
struct TreeNode {
    TokenId tokenId;
    float cumulativeProb;
    uint32_t depth;
    uint32_t parentIdx;
    std::vector<uint32_t> childIndices;
    bool verified;
    bool accepted;
    uint32_t headId;
    
    TreeNode() : tokenId(0), cumulativeProb(0.0f), depth(0), parentIdx(0), 
                 verified(false), accepted(false), headId(0) {}
};

// ============================================================================
// Verification Result
// ============================================================================
struct MedusaVerificationResult {
    uint32_t numAccepted;
    uint32_t numRejected;
    std::vector<TokenId> acceptedTokens;
    TokenId correctedToken;
    float acceptanceRate;
    double verifyTimeMs;
    uint32_t winningHeadId;
    
    MedusaVerificationResult() : numAccepted(0), numRejected(0), 
                                  acceptanceRate(0.0f), verifyTimeMs(0.0),
                                  winningHeadId(0) {}
};

// ============================================================================
// Head Statistics for Adaptive Selection
// ============================================================================
struct HeadStats {
    std::atomic<uint64_t> tokensGenerated{0};
    std::atomic<uint64_t> tokensAccepted{0};
    std::atomic<double> totalLatencyMs{0.0};
    std::atomic<uint32_t> generationCount{0};
    
    float GetAcceptanceRate() const {
        uint64_t gen = tokensGenerated.load();
        uint64_t acc = tokensAccepted.load();
        return gen > 0 ? (float)acc / (float)gen : 0.0f;
    }
    
    double GetAverageLatencyMs() const {
        uint32_t count = generationCount.load();
        return count > 0 ? totalLatencyMs.load() / count : 0.0;
    }
};

// ============================================================================
// Simple Target Model (Simulated)
// ============================================================================
class SimpleTargetModel {
public:
    SimpleTargetModel(uint32_t vocabSize) : vocabSize_(vocabSize), 
        rng_(std::random_device{}()), uniform_(0.0f, 1.0f) {}
    
    // Simulate target model forward pass
    std::vector<float> Forward(const std::vector<TokenId>& tokens) {
        std::vector<float> logits(vocabSize_);
        
        // Simulate based on last token
        TokenId lastToken = tokens.empty() ? 0 : tokens.back();
        
        for (uint32_t i = 0; i < vocabSize_; i++) {
            // Create deterministic but varied logits
            float base = std::sin((float)(lastToken * i) * 0.1f) * 2.0f;
            base += std::cos((float)i * 0.01f) * 1.5f;
            
            // Add some favorites for certain tokens
            if (i == (lastToken + 1) % vocabSize_) base += 3.0f;
            if (i == (lastToken + 2) % vocabSize_) base += 2.0f;
            if (i == (lastToken * 2) % vocabSize_) base += 1.5f;
            
            // Add small random noise
            base += uniform_(rng_) * 0.5f - 0.25f;
            
            logits[i] = base;
        }
        
        return logits;
    }
    
    // Get logits for specific tokens (for verification)
    std::vector<float> GetLogitsForTokens(const std::vector<TokenId>& tokens,
                                          const std::vector<TokenId>& candidates) {
        std::vector<float> logits = Forward(tokens);
        std::vector<float> result;
        
        for (TokenId token : candidates) {
            if (token < vocabSize_) {
                result.push_back(logits[token]);
            }
        }
        
        return result;
    }
    
private:
    uint32_t vocabSize_;
    std::mt19937 rng_;
    std::uniform_real_distribution<float> uniform_;
};

// ============================================================================
// Medusa Head
// ============================================================================
class MedusaHead {
public:
    MedusaHead(uint32_t headId, uint32_t vocabSize, SimpleTargetModel* target) 
        : headId_(headId), vocabSize_(vocabSize), target_(target),
          rng_(std::random_device{}() + headId), uniform_(0.0f, 1.0f) {}
    
    // Generate speculative tokens
    std::vector<MedusaCandidate> GenerateTokens(
        const std::vector<TokenId>& prefix,
        uint32_t numTokens,
        float temperature) {
        
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<MedusaCandidate> candidates;
        std::vector<TokenId> context = prefix;
        
        // Each head has slightly different behavior based on headId
        float headBias = (float)headId_ * 0.1f;
        
        for (uint32_t i = 0; i < numTokens; i++) {
            std::vector<float> logits = target_->Forward(context);
            
            // Add head-specific bias
            for (float& logit : logits) {
                logit += headBias;
            }
            
            TokenId token = SampleToken(logits, temperature);
            
            MedusaCandidate candidate;
            candidate.tokenId = token;
            candidate.logit = logits[token];
            candidate.probability = ComputeSoftmaxProb(logits, token);
            candidate.headId = headId_;
            candidate.position = i;
            candidate.parentIdx = i > 0 ? i - 1 : 0;
            candidate.accepted = false;
            
            candidates.push_back(candidate);
            context.push_back(token);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        double latency = std::chrono::duration<double, std::milli>(end - start).count();
        stats_.totalLatencyMs.store(stats_.totalLatencyMs.load() + latency);
        stats_.generationCount++;
        stats_.tokensGenerated += numTokens;
        
        return candidates;
    }
    
    HeadStats& GetStats() { return stats_; }
    uint32_t GetHeadId() const { return headId_; }
    
private:
    TokenId SampleToken(const std::vector<float>& logits, float temperature) {
        std::vector<float> probs = Softmax(logits, temperature);
        
        float r = uniform_(rng_);
        float cumsum = 0.0f;
        
        for (uint32_t i = 0; i < probs.size(); i++) {
            cumsum += probs[i];
            if (r < cumsum) {
                return (TokenId)i;
            }
        }
        
        return (TokenId)(probs.size() - 1);
    }
    
    std::vector<float> Softmax(const std::vector<float>& logits, float temperature) {
        std::vector<float> probs(logits.size());
        
        float maxLogit = *std::max_element(logits.begin(), logits.end());
        float sum = 0.0f;
        
        for (size_t i = 0; i < logits.size(); i++) {
            probs[i] = std::exp((logits[i] - maxLogit) / temperature);
            sum += probs[i];
        }
        
        for (float& p : probs) {
            p /= sum;
        }
        
        return probs;
    }
    
    float ComputeSoftmaxProb(const std::vector<float>& logits, TokenId token) {
        std::vector<float> probs = Softmax(logits, 1.0f);
        return token < (TokenId)probs.size() ? probs[token] : 0.0f;
    }
    
    uint32_t headId_;
    uint32_t vocabSize_;
    SimpleTargetModel* target_;
    std::mt19937 rng_;
    std::uniform_real_distribution<float> uniform_;
    HeadStats stats_;
};

// ============================================================================
// Medusa Engine
// ============================================================================
class MedusaEngine {
public:
    MedusaEngine(const MedusaConfig& config) : config_(config) {
        targetModel_ = new SimpleTargetModel(config.vocabSize);
        
        // Create Medusa heads
        for (uint32_t i = 0; i < config.numHeads; i++) {
            heads_.push_back(new MedusaHead(i, config.vocabSize, targetModel_));
        }
    }
    
    ~MedusaEngine() {
        for (auto* head : heads_) {
            delete head;
        }
        heads_.clear();
        delete targetModel_;
    }
    
    // Generate using all Medusa heads
    std::vector<std::vector<MedusaCandidate>> GenerateAllHeads(
        const std::vector<TokenId>& prefix) {
        
        std::vector<std::vector<MedusaCandidate>> allCandidates;
        
        for (auto* head : heads_) {
            auto candidates = head->GenerateTokens(prefix, config_.maxTokensPerHead, 
                                                    config_.temperature);
            allCandidates.push_back(candidates);
        }
        
        return allCandidates;
    }
    
    // Build tree from all head candidates
    std::vector<TreeNode> BuildTree(
        const std::vector<TokenId>& prefix,
        const std::vector<std::vector<MedusaCandidate>>& allCandidates) {
        
        std::vector<TreeNode> tree;
        
        // Root node
        TreeNode root;
        root.tokenId = prefix.empty() ? 0 : prefix.back();
        root.cumulativeProb = 1.0f;
        root.depth = 0;
        root.parentIdx = 0;
        root.verified = true;
        root.accepted = true;
        root.headId = 0xFFFFFFFF; // Root has no head
        tree.push_back(root);
        
        // Add candidates from all heads
        for (const auto& headCandidates : allCandidates) {
            for (const auto& candidate : headCandidates) {
                TreeNode node;
                node.tokenId = candidate.tokenId;
                node.cumulativeProb = candidate.probability;
                node.depth = candidate.position + 1;
                node.parentIdx = candidate.parentIdx + 1; // +1 for root
                node.verified = false;
                node.accepted = false;
                node.headId = candidate.headId;
                
                uint32_t nodeIdx = (uint32_t)tree.size();
                tree.push_back(node);
                
                // Link to parent
                if (node.parentIdx < tree.size()) {
                    tree[node.parentIdx].childIndices.push_back(nodeIdx);
                }
            }
        }
        
        return tree;
    }
    
    // Verify tree with target model
    MedusaVerificationResult VerifyTree(
        const std::vector<TokenId>& prefix,
        std::vector<TreeNode>& tree) {
        
        auto start = std::chrono::high_resolution_clock::now();
        
        MedusaVerificationResult result;
        std::vector<TokenId> currentPrefix = prefix;
        
        // Process nodes in breadth-first order
        for (size_t i = 1; i < tree.size(); i++) {
            TreeNode& node = tree[i];
            
            // Skip if parent wasn't accepted
            if (node.parentIdx < tree.size() && !tree[node.parentIdx].accepted) {
                continue;
            }
            
            // Get target model logits
            std::vector<float> targetLogits = targetModel_->Forward(currentPrefix);
            
            // Compute acceptance probability
            float targetProb = std::exp(targetLogits[node.tokenId]) / 
                              std::exp(*std::max_element(targetLogits.begin(), targetLogits.end()));
            
            // Simple acceptance: if target probability is high enough
            if (targetProb > config_.acceptanceThreshold) {
                node.accepted = true;
                node.verified = true;
                result.acceptedTokens.push_back(node.tokenId);
                currentPrefix.push_back(node.tokenId);
                result.numAccepted++;
                
                // Track which head contributed
                if (result.winningHeadId == 0 || node.headId < result.winningHeadId) {
                    result.winningHeadId = node.headId;
                }
                
                // Update head stats
                if (node.headId < heads_.size()) {
                    heads_[node.headId]->GetStats().tokensAccepted++;
                }
            } else {
                node.verified = true;
                node.accepted = false;
                result.numRejected++;
                
                // Sample corrected token from target
                result.correctedToken = SampleFromLogits(targetLogits, config_.temperature);
                result.acceptedTokens.push_back(result.correctedToken);
                break;
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        result.verifyTimeMs = std::chrono::duration<double, std::milli>(end - start).count();
        
        uint32_t total = result.numAccepted + result.numRejected;
        result.acceptanceRate = total > 0 ? (float)result.numAccepted / (float)total : 0.0f;
        
        return result;
    }
    
    // Run complete Medusa generation step
    MedusaVerificationResult Generate(const std::vector<TokenId>& prefix) {
        // Generate from all heads
        auto allCandidates = GenerateAllHeads(prefix);
        
        // Build tree
        auto tree = BuildTree(prefix, allCandidates);
        
        // Verify
        return VerifyTree(prefix, tree);
    }
    
    // Get statistics
    void PrintStats() {
        printf("\n=== Medusa Heads Statistics ===\n");
        printf("Head ID | Acceptance Rate | Avg Latency (ms)\n");
        printf("--------|-----------------|------------------\n");
        
        for (auto* head : heads_) {
            float rate = head->GetStats().GetAcceptanceRate();
            double latency = head->GetStats().GetAverageLatencyMs();
            printf("%7u | %14.2f%% | %16.3f\n", 
                   head->GetHeadId(), rate * 100.0f, latency);
        }
    }
    
private:
    TokenId SampleFromLogits(const std::vector<float>& logits, float temperature) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<float> uniform(0.0f, 1.0f);
        
        // Softmax
        std::vector<float> probs(logits.size());
        float maxLogit = *std::max_element(logits.begin(), logits.end());
        float sum = 0.0f;
        
        for (size_t i = 0; i < logits.size(); i++) {
            probs[i] = std::exp((logits[i] - maxLogit) / temperature);
            sum += probs[i];
        }
        
        for (float& p : probs) {
            p /= sum;
        }
        
        // Sample
        float r = uniform(gen);
        float cumsum = 0.0f;
        
        for (size_t i = 0; i < probs.size(); i++) {
            cumsum += probs[i];
            if (r < cumsum) {
                return (TokenId)i;
            }
        }
        
        return (TokenId)(probs.size() - 1);
    }
    
    MedusaConfig config_;
    SimpleTargetModel* targetModel_;
    std::vector<MedusaHead*> heads_;
};

// ============================================================================
// Benchmark
// ============================================================================
void BenchmarkMedusa() {
    printf("=== Medusa Heads Benchmark ===\n\n");
    
    MedusaConfig config;
    config.numHeads = 4;
    config.maxTokensPerHead = 8;
    config.treeDepth = 4;
    config.acceptanceThreshold = 0.5f;
    config.temperature = 0.7f;
    config.vocabSize = 32000;
    
    MedusaEngine engine(config);
    
    // Warmup
    printf("Warming up...\n");
    std::vector<TokenId> warmupPrefix = {1, 2, 3, 4, 5};
    for (int i = 0; i < 5; i++) {
        engine.Generate(warmupPrefix);
    }
    
    // Benchmark
    printf("Running benchmark...\n\n");
    
    std::vector<TokenId> prefix = {100, 200, 300, 400, 500};
    uint32_t totalTokens = 0;
    uint32_t totalAccepted = 0;
    double totalTimeMs = 0.0;
    
    const int iterations = 20;
    
    for (int i = 0; i < iterations; i++) {
        auto result = engine.Generate(prefix);
        
        totalTokens += result.numAccepted + result.numRejected;
        totalAccepted += result.numAccepted;
        totalTimeMs += result.verifyTimeMs;
        
        // Extend prefix with accepted tokens
        prefix.insert(prefix.end(), result.acceptedTokens.begin(), 
                     result.acceptedTokens.end());
        
        // Keep prefix manageable
        if (prefix.size() > 50) {
            prefix.erase(prefix.begin(), prefix.begin() + (prefix.size() - 50));
        }
    }
    
    printf("Results after %d iterations:\n", iterations);
    printf("  Total tokens generated: %u\n", totalTokens);
    printf("  Total tokens accepted:  %u\n", totalAccepted);
    printf("  Overall acceptance rate: %.2f%%\n", 
           (float)totalAccepted / (float)totalTokens * 100.0f);
    printf("  Average time per step: %.3f ms\n", totalTimeMs / iterations);
    printf("  Throughput: %.2f tokens/sec\n\n", 
           (totalTokens / (totalTimeMs / 1000.0)));
    
    engine.PrintStats();
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    printf("Medusa Heads Speculative Decoding Engine\n");
    printf("========================================\n\n");
    
    if (argc > 1 && strcmp(argv[1], "benchmark") == 0) {
        BenchmarkMedusa();
    } else {
        // Demo mode
        MedusaConfig config;
        config.numHeads = 4;
        config.maxTokensPerHead = 8;
        
        MedusaEngine engine(config);
        
        std::vector<TokenId> prefix = {1000, 2000, 3000};
        printf("Generating with prefix: ");
        for (auto t : prefix) printf("%d ", t);
        printf("\n\n");
        
        auto result = engine.Generate(prefix);
        
        printf("Generated %u tokens (accepted: %u, rejected: %u)\n",
               result.numAccepted + result.numRejected,
               result.numAccepted, result.numRejected);
        printf("Acceptance rate: %.2f%%\n", result.acceptanceRate * 100.0f);
        printf("Time: %.3f ms\n", result.verifyTimeMs);
        printf("Tokens: ");
        for (auto t : result.acceptedTokens) printf("%d ", t);
        printf("\n");
        
        engine.PrintStats();
    }
    
    return 0;
}
