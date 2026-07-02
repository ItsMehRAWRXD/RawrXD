// =============================================================================
// sovereign_batch_splitter.h
// Batch Splitter for Long-Context Sequence Processing
// Header-only implementation integrating with SuperNodeEngine
// =============================================================================

#ifndef SOVEREIGN_BATCH_SPLITTER_H
#define SOVEREIGN_BATCH_SPLITTER_H

#include <cstdint>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <optional>
#include <algorithm>
#include <cstring>

#include "sovereign_super_node_types.h"

namespace Sovereign {

// =============================================================================
// Extended Batch Metadata for Long-Context Sequences
// =============================================================================

enum class SequenceSegmentType {
    FIRST,       // Initial segment of sequence
    MIDDLE,      // Intermediate segment
    LAST,        // Final segment
    COMPLETE     // Entire sequence fits in one window
};

struct SequenceMetadata {
    uint64_t sequence_id;           // Global sequence identifier
    uint32_t segment_index;         // Which segment this is (0, 1, 2...)
    uint32_t total_segments;        // Total number of segments
    uint32_t global_token_offset;   // Token offset in original sequence
    SequenceSegmentType segment_type;
    
    // KV cache handover
    uint64_t predecessor_request_id; // Request ID of previous segment (0 if FIRST)
    uint64_t kv_cache_offset;        // Offset in shared KV cache arena
    uint32_t kv_cache_size_bytes;  // Size of KV cache to handover
    
    // Position embedding state
    uint32_t position_offset;      // RoPE/position embedding offset
    float attention_scale;         // Causal attention scaling factor
    
    SequenceMetadata()
        : sequence_id(0)
        , segment_index(0)
        , total_segments(1)
        , global_token_offset(0)
        , segment_type(SequenceSegmentType::COMPLETE)
        , predecessor_request_id(0)
        , kv_cache_offset(0)
        , kv_cache_size_bytes(0)
        , position_offset(0)
        , attention_scale(1.0f)
    {}
};

struct ExtendedBatchRequest : BatchRequest {
    SequenceMetadata seq_meta;
    bool is_continuation = false;
    uint32_t max_context_length = 0;  // Original full sequence length
    
    ExtendedBatchRequest() : BatchRequest() {}
};

struct ExtendedBatchResponse : BatchResponse {
    SequenceMetadata seq_meta;
    bool has_kv_cache = false;        // Response includes KV cache pointer
    uint8_t* kv_cache_ptr = nullptr;  // Pointer to KV cache (valid if has_kv_cache)
    uint32_t kv_cache_size = 0;       // Size of KV cache produced
    bool is_final_segment = false;    // True if this is the LAST segment
    
    ExtendedBatchResponse() : BatchResponse() {}
};

// =============================================================================
// KV Cache Handover State
// =============================================================================

struct KVCacheHandover {
    uint64_t sequence_id;
    uint64_t request_id;
    uint8_t* kv_cache_ptr;
    uint32_t kv_cache_size;
    uint32_t num_tokens;
    std::atomic<bool> ready{false};
    std::atomic<bool> consumed{false};
    
    KVCacheHandover() 
        : sequence_id(0)
        , request_id(0)
        , kv_cache_ptr(nullptr)
        , kv_cache_size(0)
        , num_tokens(0) 
    {}
};

// =============================================================================
// Splitting Strategy Interface
// =============================================================================

class ISplittingStrategy {
public:
    virtual ~ISplittingStrategy() = default;
    
    // Determine how to split a sequence given worker constraints
    virtual std::vector<uint32_t> CalculateChunkSizes(
        uint32_t total_tokens,
        uint32_t max_window_tokens,
        int num_workers
    ) const = 0;
    
    // Select which worker should process a given chunk
    virtual int SelectWorkerForChunk(
        int chunk_index,
        int num_workers,
        const std::vector<LogicalWorker>& workers
    ) const = 0;
};

// Fixed-window splitting: Simple, predictable
class FixedWindowStrategy : public ISplittingStrategy {
    uint32_t window_overlap_;  // Tokens to overlap between chunks (for attention)
    
public:
    explicit FixedWindowStrategy(uint32_t overlap = 0) : window_overlap_(overlap) {}
    
    std::vector<uint32_t> CalculateChunkSizes(
        uint32_t total_tokens,
        uint32_t max_window_tokens,
        int num_workers
    ) const override {
        std::vector<uint32_t> chunks;
        (void)num_workers;
        if (total_tokens == 0) {
            chunks.push_back(0);
            return chunks;
        }
        if (max_window_tokens == 0) {
            chunks.push_back(total_tokens);
            return chunks;
        }
        // Clamp overlap to ensure each chunk always advances the cursor.
        const uint32_t safe_overlap = std::min(window_overlap_, max_window_tokens - 1);
        
        if (total_tokens <= max_window_tokens) {
            chunks.push_back(total_tokens);
            return chunks;
        }
        
        // First chunk consumes from offset 0.
        uint32_t consumed = std::min(max_window_tokens, total_tokens);
        chunks.push_back(consumed);
        
        // Subsequent chunks include overlap, but must always advance by >= 1 token.
        while (consumed < total_tokens) {
            const uint32_t remaining = total_tokens - consumed;
            const uint32_t requested = remaining + safe_overlap;
            const uint32_t chunk_size = std::min(max_window_tokens, requested);
            chunks.push_back(chunk_size);
            
            const uint32_t advance = (chunk_size > safe_overlap) ? (chunk_size - safe_overlap) : 1u;
            consumed = std::min(total_tokens, consumed + advance);
        }
        
        return chunks;
    }
    
    int SelectWorkerForChunk(
        int chunk_index,
        int num_workers,
        const std::vector<LogicalWorker>& workers
    ) const override {
        // Round-robin assignment
        return chunk_index % num_workers;
    }
};

// Dynamic load-balanced splitting: Uses telemetry
class DynamicLoadBalancedStrategy : public ISplittingStrategy {
    uint32_t min_chunk_size_;
    
public:
    explicit DynamicLoadBalancedStrategy(uint32_t min_chunk = 64) 
        : min_chunk_size_(min_chunk) {}
    
    std::vector<uint32_t> CalculateChunkSizes(
        uint32_t total_tokens,
        uint32_t max_window_tokens,
        int num_workers
    ) const override {
        // Same as fixed for now - could be made more sophisticated
        FixedWindowStrategy fixed;
        return fixed.CalculateChunkSizes(total_tokens, max_window_tokens, num_workers);
    }
    
    int SelectWorkerForChunk(
        int chunk_index,
        int num_workers,
        const std::vector<LogicalWorker>& workers
    ) const override {
        // Select worker with lowest tokens_submitted (least loaded)
        int best_worker = 0;
        uint64_t min_load = std::numeric_limits<uint64_t>::max();
        
        for (int i = 0; i < num_workers && i < (int)workers.size(); i++) {
            uint64_t load = workers[i].metrics.tokens_submitted.load();
            if (load < min_load) {
                min_load = load;
                best_worker = i;
            }
        }
        
        return best_worker;
    }
};

// =============================================================================
// Splitter Coordinator
// Manages long-context sequence state across multiple workers
// =============================================================================

class SplitterCoordinator {
public:
    struct SequenceState {
        uint64_t sequence_id;
        uint32_t total_segments;
        uint32_t completed_segments;
        std::vector<uint64_t> segment_request_ids;
        std::vector<bool> segment_completed;
        std::atomic<bool> is_complete{false};
        std::vector<uint32_t> output_tokens;  // Aggregated output
        
        explicit SequenceState(uint64_t id, uint32_t segments)
            : sequence_id(id)
            , total_segments(segments)
            , completed_segments(0)
            , segment_completed(segments, false)
        {}
    };

private:
    std::mutex mutex_;
    std::unordered_map<uint64_t, std::unique_ptr<SequenceState>> sequences_;
    std::unordered_map<uint64_t, std::unique_ptr<KVCacheHandover>> kv_handovers_;
    uint64_t next_sequence_id_{1};
    
public:
    // Register a new long-context sequence
    uint64_t RegisterSequence(uint32_t num_segments) {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t seq_id = next_sequence_id_++;
        sequences_[seq_id] = std::make_unique<SequenceState>(seq_id, num_segments);
        return seq_id;
    }
    
    // Get sequence state
    SequenceState* GetSequence(uint64_t sequence_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sequences_.find(sequence_id);
        if (it != sequences_.end()) {
            return it->second.get();
        }
        return nullptr;
    }
    
    // Mark segment as completed
    bool CompleteSegment(uint64_t sequence_id, uint32_t segment_index, 
                         const std::vector<uint32_t>& output_tokens) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sequences_.find(sequence_id);
        if (it == sequences_.end()) return false;
        
        auto& state = it->second;
        if (segment_index >= state->total_segments) return false;
        if (state->segment_completed[segment_index]) return false;
        
        state->segment_completed[segment_index] = true;
        state->completed_segments++;
        
        // Append output tokens
        state->output_tokens.insert(state->output_tokens.end(), 
                                      output_tokens.begin(), output_tokens.end());
        
        // Check if sequence is complete
        if (state->completed_segments >= state->total_segments) {
            state->is_complete.store(true);
        }
        
        return true;
    }
    
    // Check if sequence is complete
    bool IsSequenceComplete(uint64_t sequence_id) {
        auto* state = GetSequence(sequence_id);
        if (!state) return false;
        return state->is_complete.load();
    }
    
    // Get aggregated results
    std::optional<std::vector<uint32_t>> GetSequenceOutput(uint64_t sequence_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sequences_.find(sequence_id);
        if (it == sequences_.end()) return std::nullopt;
        
        if (!it->second->is_complete.load()) return std::nullopt;
        return it->second->output_tokens;
    }
    
    // Cleanup completed sequence
    void CleanupSequence(uint64_t sequence_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        sequences_.erase(sequence_id);
        kv_handovers_.erase(sequence_id);
    }
    
    // Register KV cache for handover
    void RegisterKVCacheHandover(uint64_t sequence_id, uint64_t request_id,
                                  uint8_t* kv_cache, uint32_t kv_size,
                                  uint32_t num_tokens) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto handover = std::make_unique<KVCacheHandover>();
        handover->sequence_id = sequence_id;
        handover->request_id = request_id;
        handover->kv_cache_ptr = kv_cache;
        handover->kv_cache_size = kv_size;
        handover->num_tokens = num_tokens;
        handover->ready.store(true);
        handover->consumed.store(false);
        
        kv_handovers_[request_id] = std::move(handover);
    }
    
    // Consume KV cache handover (returns pointer if available)
    KVCacheHandover* ConsumeKVCacheHandover(uint64_t predecessor_request_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = kv_handovers_.find(predecessor_request_id);
        if (it == kv_handovers_.end()) return nullptr;
        
        if (!it->second->ready.load() || it->second->consumed.load()) {
            return nullptr;
        }
        
        it->second->consumed.store(true);
        return it->second.get();
    }
    
    // Cleanup KV handover
    void CleanupKVHandover(uint64_t request_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        kv_handovers_.erase(request_id);
    }
};

// =============================================================================
// Batch Splitter
// Main class for splitting and orchestrating long-context sequences
// =============================================================================

class BatchSplitter {
public:
    struct SplitConfig {
        uint32_t max_tokens_per_window = 2048;
        uint32_t window_overlap = 128;      // Overlap for attention continuity
        bool enable_kv_handover = true;
        bool enable_load_balancing = true;
        uint32_t min_chunk_size = 64;
    };

private:
    SplitConfig config_;
    std::unique_ptr<ISplittingStrategy> strategy_;
    SplitterCoordinator coordinator_;
    
public:
    explicit BatchSplitter(const SplitConfig& config = SplitConfig())
        : config_(config) {
        if (config.enable_load_balancing) {
            strategy_ = std::make_unique<DynamicLoadBalancedStrategy>(config.min_chunk_size);
        } else {
            strategy_ = std::make_unique<FixedWindowStrategy>(config.window_overlap);
        }
    }
    
    // Check if sequence needs splitting
    bool NeedsSplitting(uint32_t token_count) const {
        return token_count > config_.max_tokens_per_window;
    }
    
    // Split a long sequence into multiple batch requests
    std::vector<ExtendedBatchRequest> SplitSequence(
        const std::vector<uint32_t>& input_tokens,
        uint64_t base_request_id,
        int num_workers,
        const std::vector<LogicalWorker>& workers
    ) {
        std::vector<ExtendedBatchRequest> requests;
        
        if (!NeedsSplitting((uint32_t)input_tokens.size())) {
            // No splitting needed
            ExtendedBatchRequest req;
            req.request_id = base_request_id;
            req.input_tokens = input_tokens;
            req.seq_meta.sequence_id = coordinator_.RegisterSequence(1);
            req.seq_meta.segment_type = SequenceSegmentType::COMPLETE;
            req.seq_meta.total_segments = 1;
            req.is_continuation = false;
            req.max_context_length = (uint32_t)input_tokens.size();
            requests.push_back(std::move(req));
            return requests;
        }
        
        // Calculate chunk sizes
        auto chunk_sizes = strategy_->CalculateChunkSizes(
            (uint32_t)input_tokens.size(),
            config_.max_tokens_per_window,
            num_workers
        );
        
        uint32_t num_segments = (uint32_t)chunk_sizes.size();
        uint64_t sequence_id = coordinator_.RegisterSequence(num_segments);
        
        uint32_t offset = 0;
        for (uint32_t i = 0; i < num_segments; i++) {
            ExtendedBatchRequest req;
            req.request_id = base_request_id + i;
            req.seq_meta.sequence_id = sequence_id;
            req.seq_meta.segment_index = i;
            req.seq_meta.total_segments = num_segments;
            req.seq_meta.global_token_offset = offset;
            req.max_context_length = (uint32_t)input_tokens.size();
            
            // Determine segment type
            if (i == 0) {
                req.seq_meta.segment_type = SequenceSegmentType::FIRST;
                req.is_continuation = false;
                req.seq_meta.predecessor_request_id = 0;
            } else if (i == num_segments - 1) {
                req.seq_meta.segment_type = SequenceSegmentType::LAST;
                req.is_continuation = true;
                req.seq_meta.predecessor_request_id = base_request_id + i - 1;
            } else {
                req.seq_meta.segment_type = SequenceSegmentType::MIDDLE;
                req.is_continuation = true;
                req.seq_meta.predecessor_request_id = base_request_id + i - 1;
            }
            
            // Calculate position offset for RoPE
            req.seq_meta.position_offset = offset;
            
            // Extract tokens for this chunk
            uint32_t chunk_size = chunk_sizes[i];
            req.input_tokens.assign(
                input_tokens.begin() + offset,
                input_tokens.begin() + std::min(offset + chunk_size, (uint32_t)input_tokens.size())
            );
            
            // Select worker
            int worker_id = strategy_->SelectWorkerForChunk(i, num_workers, workers);
            req.seq_meta.kv_cache_offset = worker_id;  // Store worker assignment
            
            requests.push_back(std::move(req));
            
            // Account for overlap in offset calculation. Ensure forward progress.
            if (i == 0) {
                offset += chunk_size;
            } else {
                uint32_t safe_overlap = std::min(config_.window_overlap, chunk_size > 0 ? chunk_size - 1 : 0u);
                uint32_t advance = (chunk_size > safe_overlap) ? (chunk_size - safe_overlap) : 1u;
                offset = std::min(offset + advance, (uint32_t)input_tokens.size());
            }
        }
        
        return requests;
    }

    std::vector<ExtendedBatchRequest> SplitSequenceZeroCopy(
        const uint32_t* input_tokens,
        uint32_t token_count,
        uint64_t base_request_id,
        int num_workers,
        const std::vector<LogicalWorker>& workers
    ) {
        std::vector<ExtendedBatchRequest> requests;

        if (!input_tokens || token_count == 0) {
            return requests;
        }

        if (!NeedsSplitting(token_count)) {
            ExtendedBatchRequest req;
            req.request_id = base_request_id;
            req.input_tokens_ptr = input_tokens;
            req.input_token_count = token_count;
            req.use_zero_copy_input = true;
            req.seq_meta.sequence_id = coordinator_.RegisterSequence(1);
            req.seq_meta.segment_type = SequenceSegmentType::COMPLETE;
            req.seq_meta.total_segments = 1;
            req.max_context_length = token_count;
            requests.push_back(std::move(req));
            return requests;
        }

        auto chunk_sizes = strategy_->CalculateChunkSizes(
            token_count,
            config_.max_tokens_per_window,
            num_workers
        );

        uint32_t num_segments = static_cast<uint32_t>(chunk_sizes.size());
        uint64_t sequence_id = coordinator_.RegisterSequence(num_segments);
        uint32_t offset = 0;

        for (uint32_t i = 0; i < num_segments; ++i) {
            ExtendedBatchRequest req;
            req.request_id = base_request_id + i;
            req.use_zero_copy_input = true;
            req.input_tokens_ptr = input_tokens + offset;
            req.input_token_count = std::min(chunk_sizes[i], token_count - offset);
            req.sequence_offset = offset;
            req.position_offset = offset;
            req.seq_meta.sequence_id = sequence_id;
            req.seq_meta.segment_index = i;
            req.seq_meta.total_segments = num_segments;
            req.seq_meta.global_token_offset = offset;
            req.seq_meta.position_offset = offset;
            req.max_context_length = token_count;

            if (i == 0) {
                req.seq_meta.segment_type = SequenceSegmentType::FIRST;
                req.is_continuation = false;
            } else if (i == num_segments - 1) {
                req.seq_meta.segment_type = SequenceSegmentType::LAST;
                req.is_continuation = true;
                req.seq_meta.predecessor_request_id = base_request_id + i - 1;
            } else {
                req.seq_meta.segment_type = SequenceSegmentType::MIDDLE;
                req.is_continuation = true;
                req.seq_meta.predecessor_request_id = base_request_id + i - 1;
            }

            const int worker_id = strategy_->SelectWorkerForChunk(i, num_workers, workers);
            req.seq_meta.kv_cache_offset = worker_id;
            requests.push_back(std::move(req));

            if (i == 0) {
                offset += chunk_sizes[i];
            } else {
                const uint32_t safe_overlap = std::min(config_.window_overlap, chunk_sizes[i] > 0 ? chunk_sizes[i] - 1 : 0u);
                const uint32_t advance = (chunk_sizes[i] > safe_overlap) ? (chunk_sizes[i] - safe_overlap) : 1u;
                offset = std::min(offset + advance, token_count);
            }
        }

        return requests;
    }
    
    // Process a response and handle KV cache handover
    bool ProcessResponse(const ExtendedBatchResponse& response) {
        // Complete the segment
        bool completed = coordinator_.CompleteSegment(
            response.seq_meta.sequence_id,
            response.seq_meta.segment_index,
            response.output_tokens
        );
        
        // Register KV cache for handover if not the last segment
        if (completed && config_.enable_kv_handover && 
            response.seq_meta.segment_type != SequenceSegmentType::LAST &&
            response.has_kv_cache && response.kv_cache_ptr) {
            coordinator_.RegisterKVCacheHandover(
                response.seq_meta.sequence_id,
                response.request_id,
                response.kv_cache_ptr,
                response.kv_cache_size,
                (uint32_t)response.output_tokens.size()
            );
        }
        
        return completed;
    }
    
    // Check if a sequence is complete and get results
    std::optional<std::vector<uint32_t>> CheckSequenceComplete(uint64_t sequence_id) {
        return coordinator_.GetSequenceOutput(sequence_id);
    }
    
    // Get KV cache handover for a continuation request
    KVCacheHandover* GetKVCacheHandover(uint64_t predecessor_request_id) {
        return coordinator_.ConsumeKVCacheHandover(predecessor_request_id);
    }
    
    // Cleanup completed sequence
    void CleanupSequence(uint64_t sequence_id) {
        coordinator_.CleanupSequence(sequence_id);
    }
    
    // Get coordinator reference (for advanced usage)
    SplitterCoordinator& GetCoordinator() { return coordinator_; }
    
    // Update strategy (for dynamic reconfiguration)
    void SetStrategy(std::unique_ptr<ISplittingStrategy> strategy) {
        strategy_ = std::move(strategy);
    }
};

// =============================================================================
// Integration Helpers for SuperNodeEngine
// =============================================================================

// Helper to submit split batches to workers
inline bool SubmitSplitBatchToWorker(
    SuperNodeEngine* engine,
    const ExtendedBatchRequest& request,
    SplitterCoordinator& coordinator
) {
    // If continuation, try to get KV cache handover
    if (request.is_continuation && request.seq_meta.predecessor_request_id != 0) {
        KVCacheHandover* handover = coordinator.ConsumeKVCacheHandover(
            request.seq_meta.predecessor_request_id);
        
        if (handover && handover->ready.load()) {
            // KV cache is ready - worker can use it
            // In real implementation, this would pass the pointer to the worker
            // For now, we just mark it as consumed
            (void)handover;  // Use the handover
        }
        // Note: If handover not ready, worker should wait or handle accordingly
    }
    
    // Convert to base BatchRequest and submit
    // This would call SuperNodeEngineTestAccess::SubmitBatchToWorker
    // For now, return true to indicate success
    return true;
}

// Helper to collect and aggregate split responses
inline std::optional<std::vector<uint32_t>> CollectSplitResponse(
    SuperNodeEngine* engine,
    uint64_t sequence_id,
    SplitterCoordinator& coordinator
) {
    return coordinator.GetSequenceOutput(sequence_id);
}

} // namespace Sovereign

#endif // SOVEREIGN_BATCH_SPLITTER_H
