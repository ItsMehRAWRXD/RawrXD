#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <memory>
#include <atomic>

// ═══════════════════════════════════════════════════════════════════════════════
// VAL-032: Speculative Execution Scheduler (Phase 1)
// ═══════════════════════════════════════════════════════════════════════════════
// Separates the speculation logic from the math, enabling validation of:
//   - acceptance rate
//   - queue depth
//   - rollback logic
//   - branch prediction
//   - telemetry
// Before evolving the kernel itself.
// ═══════════════════════════════════════════════════════════════════════════════

namespace RawrXD {

// ═══════════════════════════════════════════════════════════════════════════════
// Configuration Constants
// ═══════════════════════════════════════════════════════════════════════════════
constexpr uint32_t SPEC_MAX_DRAFT_DEPTH = 5;           // Max tokens to speculate ahead
constexpr uint32_t SPEC_MAX_BRANCHING_FACTOR = 4;        // Max branches per node
constexpr uint32_t SPEC_CANDIDATE_QUEUE_SIZE = 256;    // Power of 2 for fast mask
constexpr uint32_t SPEC_ACCEPTANCE_THRESHOLD = 0;      // Token ID match threshold (exact)

// ═══════════════════════════════════════════════════════════════════════════════
// Telemetry Counters (Cache-aligned to prevent false sharing)
// ═══════════════════════════════════════════════════════════════════════════════
struct alignas(64) SpeculativeTelemetry {
    std::atomic<uint64_t> draftTokensGenerated{0};      // Total draft tokens created
    std::atomic<uint64_t> tokensVerified{0};          // Tokens sent through verification
    std::atomic<uint64_t> tokensAccepted{0};           // Tokens that matched target
    std::atomic<uint64_t> rollbacksExecuted{0};         // Rollback operations
    std::atomic<uint64_t> branchesExplored{0};          // Total branches evaluated
    std::atomic<uint64_t> branchesPruned{0};            // Branches cut by scheduler
    std::atomic<uint64_t> verificationBatches{0};      // Number of verification passes
    std::atomic<uint64_t> falsePredictions{0};        // Accepted but later rejected
    
    // Timing (in microseconds)
    std::atomic<uint64_t> draftTimeUs{0};              // Time spent in draft generation
    std::atomic<uint64_t> verifyTimeUs{0};             // Time spent in verification
    std::atomic<uint64_t> rollbackTimeUs{0};           // Time spent in rollback
    
    // Derived metrics (computed on read)
    float GetAcceptanceRate() const {
        uint64_t verified = tokensVerified.load();
        return verified > 0 ? (float)tokensAccepted.load() / verified : 0.0f;
    }
    
    float GetAverageBranchDepth() const {
        uint64_t batches = verificationBatches.load();
        return batches > 0 ? (float)branchesExplored.load() / batches : 0.0f;
    }
    
    float GetSpeculationGain() const {
        uint64_t accepted = tokensAccepted.load();
        uint64_t verified = tokensVerified.load();
        return verified > 0 ? (float)accepted / verified : 0.0f;
    }
    
    void Reset() {
        draftTokensGenerated = 0;
        tokensVerified = 0;
        tokensAccepted = 0;
        rollbacksExecuted = 0;
        branchesExplored = 0;
        branchesPruned = 0;
        verificationBatches = 0;
        falsePredictions = 0;
        draftTimeUs = 0;
        verifyTimeUs = 0;
        rollbackTimeUs = 0;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Tree Node Structure (64-byte aligned for cache efficiency)
// ═══════════════════════════════════════════════════════════════════════════════
struct alignas(64) TreeNode {
    uint32_t token;              // Predicted token ID
    uint16_t parent;             // Parent node index (0xFFFF = root)
    uint16_t depth;              // Depth in tree (0 = root)
    float probability;             // Confidence score (0.0 - 1.0)
    uint32_t flags;              // Node state flags
    
    // Cache-friendly padding to 64 bytes
    uint32_t _pad[10];
    
    enum Flags : uint32_t {
        FLAG_VALID = 1 << 0,     // Node contains valid data
        FLAG_ACCEPTED = 1 << 1,  // Token was verified and accepted
        FLAG_REJECTED = 1 << 2,  // Token was verified and rejected
        FLAG_PRUNED = 1 << 3,    // Branch was pruned by scheduler
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// Candidate Ring Buffer (Lock-free SPSC queue)
// ═══════════════════════════════════════════════════════════════════════════════
template<typename T, size_t Capacity>
class alignas(64) CandidateRingBuffer {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
    
    std::array<T, Capacity> buffer_;
    alignas(64) std::atomic<size_t> head_{0};  // Write position
    alignas(64) std::atomic<size_t> tail_{0};  // Read position
    
public:
    static constexpr size_t MASK = Capacity - 1;
    
    bool Push(const T& item) {
        size_t h = head_.load(std::memory_order_relaxed);
        size_t next = (h + 1) & MASK;
        
        if (next == tail_.load(std::memory_order_acquire)) {
            return false; // Queue full
        }
        
        buffer_[h & MASK] = item;
        head_.store(next, std::memory_order_release);
        return true;
    }
    
    bool Pop(T& item) {
        size_t t = tail_.load(std::memory_order_relaxed);
        
        if (t == head_.load(std::memory_order_acquire)) {
            return false; // Queue empty
        }
        
        item = buffer_[t & MASK];
        tail_.store((t + 1) & MASK, std::memory_order_release);
        return true;
    }
    
    size_t Size() const {
        return (head_.load(std::memory_order_acquire) - 
                tail_.load(std::memory_order_acquire)) & MASK;
    }
    
    bool Empty() const { return Size() == 0; }
    bool Full() const { return Size() >= (Capacity - 1); }
    
    void Clear() {
        head_.store(0, std::memory_order_release);
        tail_.store(0, std::memory_order_release);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Draft Generator Interface (Pluggable)
// ═══════════════════════════════════════════════════════════════════════════════
class IDraftGenerator {
public:
    virtual ~IDraftGenerator() = default;
    
    // Generate draft tokens given context
    // Returns number of tokens generated (0 if no prediction)
    virtual uint32_t GenerateDraft(
        const uint32_t* contextTokens,     // Input token sequence
        uint32_t contextLength,             // Length of input
        TreeNode* outputDrafts,             // Output buffer for draft nodes
        uint32_t maxDrafts,                 // Max drafts to generate
        float temperature = 1.0f           // Sampling temperature
    ) = 0;
    
    // Get generator name for telemetry
    virtual const char* GetName() const = 0;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Simple N-Gram Draft Generator (Phase 1 - deterministic, no training)
// ═══════════════════════════════════════════════════════════════════════════════
class NGramDraftGenerator : public IDraftGenerator {
    static constexpr uint32_t NGRAM_SIZE = 3;
    static constexpr uint32_t MAX_VOCAB = 32000;
    
    // Simple hash table for n-gram continuations
    struct NGramEntry {
        uint32_t context[NGRAM_SIZE - 1];
        uint32_t continuation;
        uint32_t count;
        float probability;
    };
    
    std::vector<NGramEntry> ngramTable_;
    
public:
    const char* GetName() const override { return "NGramDraftGenerator"; }
    
    uint32_t GenerateDraft(
        const uint32_t* contextTokens,
        uint32_t contextLength,
        TreeNode* outputDrafts,
        uint32_t maxDrafts,
        float temperature
    ) override {
        if (contextLength < NGRAM_SIZE - 1 || maxDrafts == 0) {
            return 0;
        }
        
        // Simple n-gram lookup (deterministic for Phase 1)
        uint32_t generated = 0;
        uint32_t currentContext[NGRAM_SIZE - 1];
        
        // Initialize context from end of sequence
        for (uint32_t i = 0; i < NGRAM_SIZE - 1; i++) {
            currentContext[i] = contextTokens[contextLength - (NGRAM_SIZE - 1) + i];
        }
        
        // Generate up to maxDrafts or SPEC_MAX_DRAFT_DEPTH
        uint32_t maxToGenerate = std::min(maxDrafts, SPEC_MAX_DRAFT_DEPTH);
        
        for (uint32_t d = 0; d < maxToGenerate; d++) {
            // Look up continuation (simplified - would use hash table in production)
            uint32_t nextToken = LookupNGram(currentContext);
            
            if (nextToken == 0 || nextToken >= MAX_VOCAB) {
                break; // No valid continuation
            }
            
            // Create tree node
            outputDrafts[d].token = nextToken;
            outputDrafts[d].parent = (d == 0) ? 0xFFFF : (d - 1);
            outputDrafts[d].depth = d;
            outputDrafts[d].probability = 0.8f; // Placeholder confidence
            outputDrafts[d].flags = TreeNode::FLAG_VALID;
            
            // Update context for next iteration
            for (uint32_t i = 0; i < NGRAM_SIZE - 2; i++) {
                currentContext[i] = currentContext[i + 1];
            }
            currentContext[NGRAM_SIZE - 2] = nextToken;
            
            generated++;
        }
        
        return generated;
    }
    
private:
    uint32_t LookupNGram(const uint32_t* context) {
        // Simplified: return a deterministic continuation based on context hash
        // In production, this would query a trained n-gram model or cache
        uint32_t hash = context[0] * 31 + context[1];
        return (hash % 1000) + 1; // Return token 1-1000 based on hash
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Speculative Execution Scheduler (Phase 1 Core)
// ═══════════════════════════════════════════════════════════════════════════════
class SpeculativeScheduler {
public:
    struct Config {
        uint32_t maxDraftDepth = SPEC_MAX_DRAFT_DEPTH;
        uint32_t maxBranchingFactor = SPEC_MAX_BRANCHING_FACTOR;
        float acceptanceThreshold = 0.9f;    // Min probability to accept draft
        bool enableBranchPruning = true;      // Prune low-probability branches
    };
    
    enum class State {
        IDLE,               // Waiting for input
        DRAFTING,           // Generating draft tokens
        VERIFYING,          // Running verification through main model
        ACCEPTING,          // Accepting verified tokens
        ROLLING_BACK,       // Rolling back rejected tokens
    };
    
private:
    Config config_;
    State state_ = State::IDLE;
    
    // Components
    std::unique_ptr<IDraftGenerator> draftGenerator_;
    CandidateRingBuffer<TreeNode, SPEC_CANDIDATE_QUEUE_SIZE> candidateQueue_;
    
    // Tree storage (pre-allocated for cache efficiency)
    std::array<TreeNode, SPEC_MAX_DRAFT_DEPTH * SPEC_MAX_BRANCHING_FACTOR> treeNodes_;
    uint32_t treeNodeCount_ = 0;
    
    // Verification batch
    std::vector<uint32_t> verificationBatch_;
    
    // Telemetry
    SpeculativeTelemetry telemetry_;
    
    // Timing
    uint64_t draftStartTime_ = 0;
    uint64_t verifyStartTime_ = 0;
    uint64_t rollbackStartTime_ = 0;
    
public:
    explicit SpeculativeScheduler(const Config& cfg = {}) : config_(cfg) {
        // Default to N-gram generator for Phase 1
        draftGenerator_ = std::make_unique<NGramDraftGenerator>();
        verificationBatch_.reserve(SPEC_MAX_DRAFT_DEPTH * SPEC_MAX_BRANCHING_FACTOR);
    }
    
    void SetDraftGenerator(std::unique_ptr<IDraftGenerator> generator) {
        draftGenerator_ = std::move(generator);
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Main Inference Loop Integration
    // ═══════════════════════════════════════════════════════════════════════════
    
    // Step 1: Generate draft tokens
    // Call this before running the main model
    uint32_t GenerateDrafts(
        const uint32_t* contextTokens,
        uint32_t contextLength
    ) {
        state_ = State::DRAFTING;
        draftStartTime_ = GetTimestampUs();
        
        // Clear previous tree
        treeNodeCount_ = 0;
        for (auto& node : treeNodes_) {
            node.flags = 0;
        }
        
        // Generate draft tree
        uint32_t generated = draftGenerator_->GenerateDraft(
            contextTokens,
            contextLength,
            treeNodes_.data(),
            static_cast<uint32_t>(treeNodes_.size()),
            1.0f
        );
        
        treeNodeCount_ = generated;
        
        // Add to candidate queue
        for (uint32_t i = 0; i < generated; i++) {
            if (!candidateQueue_.Push(treeNodes_[i])) {
                break; // Queue full
            }
        }
        
        // Update telemetry
        telemetry_.draftTokensGenerated += generated;
        telemetry_.draftTimeUs += GetTimestampUs() - draftStartTime_;
        
        return generated;
    }
    
    // Step 2: Prepare verification batch
    // Returns pointer to batch of tokens to verify
    const uint32_t* PrepareVerificationBatch(uint32_t& batchSize) {
        state_ = State::VERIFYING;
        verifyStartTime_ = GetTimestampUs();
        
        verificationBatch_.clear();
        
        TreeNode node;
        while (verificationBatch_.size() < config_.maxDraftDepth && 
               candidateQueue_.Pop(node)) {
            if (node.flags & TreeNode::FLAG_VALID) {
                verificationBatch_.push_back(node.token);
            }
        }
        
        batchSize = static_cast<uint32_t>(verificationBatch_.size());
        telemetry_.tokensVerified += batchSize;
        telemetry_.verificationBatches++;
        
        return verificationBatch_.data();
    }
    
    // Step 3: Process verification results
    // verifiedTokens: tokens output by main model
    // count: number of verified tokens
    // Returns: number of tokens to accept (may be less than count if mismatch)
    uint32_t ProcessVerificationResults(
        const uint32_t* verifiedTokens,
        uint32_t count
    ) {
        uint32_t accepted = 0;
        
        for (uint32_t i = 0; i < count && i < verificationBatch_.size(); i++) {
            if (verificationBatch_[i] == verifiedTokens[i]) {
                // Token accepted
                if (i < treeNodeCount_) {
                    treeNodes_[i].flags |= TreeNode::FLAG_ACCEPTED;
                }
                accepted++;
                telemetry_.tokensAccepted++;
            } else {
                // Mismatch - reject this and all subsequent
                telemetry_.falsePredictions++;
                break;
            }
        }
        
        telemetry_.verifyTimeUs += GetTimestampUs() - verifyStartTime_;
        
        if (accepted > 0) {
            state_ = State::ACCEPTING;
        } else {
            state_ = State::ROLLING_BACK;
            rollbackStartTime_ = GetTimestampUs();
            telemetry_.rollbacksExecuted++;
            telemetry_.rollbackTimeUs += GetTimestampUs() - rollbackStartTime_;
        }
        
        return accepted;
    }
    
    // Step 4: Get accepted tokens for output
    void GetAcceptedTokens(uint32_t* output, uint32_t maxCount, uint32_t& actualCount) {
        actualCount = 0;
        for (uint32_t i = 0; i < treeNodeCount_ && actualCount < maxCount; i++) {
            if (treeNodes_[i].flags & TreeNode::FLAG_ACCEPTED) {
                output[actualCount++] = treeNodes_[i].token;
            }
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Telemetry Access
    // ═══════════════════════════════════════════════════════════════════════════
    const SpeculativeTelemetry& GetTelemetry() const { return telemetry_; }
    SpeculativeTelemetry& GetTelemetry() { return telemetry_; }
    
    void ResetTelemetry() { telemetry_.Reset(); }
    
    State GetState() const { return state_; }
    const char* GetStateString() const {
        switch (state_) {
            case State::IDLE: return "IDLE";
            case State::DRAFTING: return "DRAFTING";
            case State::VERIFYING: return "VERIFYING";
            case State::ACCEPTING: return "ACCEPTING";
            case State::ROLLING_BACK: return "ROLLING_BACK";
            default: return "UNKNOWN";
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Branch Management (Phase 3 - Adaptive Branching)
    // ═══════════════════════════════════════════════════════════════════════════
    void PruneLowProbabilityBranches(float threshold) {
        if (!config_.enableBranchPruning) return;
        
        uint32_t pruned = 0;
        for (uint32_t i = 0; i < treeNodeCount_; i++) {
            if (treeNodes_[i].probability < threshold && 
                !(treeNodes_[i].flags & TreeNode::FLAG_ACCEPTED)) {
                treeNodes_[i].flags |= TreeNode::FLAG_PRUNED;
                pruned++;
            }
        }
        
        telemetry_.branchesPruned += pruned;
    }
    
    uint32_t GetActiveBranchCount() const {
        uint32_t active = 0;
        for (uint32_t i = 0; i < treeNodeCount_; i++) {
            if ((treeNodes_[i].flags & TreeNode::FLAG_VALID) &&
                !(treeNodes_[i].flags & TreeNode::FLAG_PRUNED)) {
                active++;
            }
        }
        return active;
    }
    
private:
    static uint64_t GetTimestampUs() {
        // Platform-specific timing (simplified)
        // In production, use QueryPerformanceCounter on Windows
        static uint64_t counter = 0;
        return ++counter; // Placeholder
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Tree Batch Structure (For Phase 2 Kernel Integration)
// ═══════════════════════════════════════════════════════════════════════════════
struct TreeBatch {
    TreeNode* nodes;           // Array of tree nodes
    uint32_t count;            // Total nodes in batch
    uint32_t maxDepth;         // Maximum depth in tree
    uint32_t rootToken;        // Starting token
    
    // DAG adjacency for attention mask (compressed)
    uint32_t* parentIndices;   // Parent index per node
    uint8_t* validMask;        // Valid node bitmap
};

// ═══════════════════════════════════════════════════════════════════════════════
// Integration Helper: Convert scheduler output to TreeBatch
// ═══════════════════════════════════════════════════════════════════════════════
inline TreeBatch CreateTreeBatchFromScheduler(
    const SpeculativeScheduler& scheduler,
    TreeNode* nodeBuffer,
    uint32_t bufferSize
) {
    TreeBatch batch{};
    batch.nodes = nodeBuffer;
    batch.count = std::min(bufferSize, SPEC_MAX_DRAFT_DEPTH * SPEC_MAX_BRANCHING_FACTOR);
    batch.maxDepth = SPEC_MAX_DRAFT_DEPTH;
    batch.rootToken = 0; // Set by caller
    batch.parentIndices = nullptr; // Allocated by kernel
    batch.validMask = nullptr;
    return batch;
}

} // namespace RawrXD
