// ============================================================================
// sovereign_batch_splitter.hpp - Minimal batch splitter for E2E testing
// ============================================================================

#ifndef SOVEREIGN_BATCH_SPLITTER_HPP
#define SOVEREIGN_BATCH_SPLITTER_HPP

#include <vector>
#include <cstdint>

namespace Sovereign {

// ============================================================================
// Splitter Configuration
// ============================================================================
struct SplitterConfig {
    size_t max_batch_size = 512;      // Maximum tokens per batch
    size_t overlap_tokens = 0;         // Number of overlapping tokens between batches
    bool enable_overlap = false;       // Enable overlapping windows
};

// ============================================================================
// Token Batch
// ============================================================================
struct TokenBatch {
    std::vector<int32_t> tokens;      // Token IDs
    std::vector<int32_t> positions;    // Position offsets for RoPE
    size_t position_offset = 0;        // Starting position in sequence
};

// ============================================================================
// Batch Splitter
// ============================================================================
class BatchSplitter {
public:
    BatchSplitter() : initialized_(false) {}
    
    bool Initialize(const SplitterConfig& config) {
        config_ = config;
        initialized_ = true;
        return true;
    }
    
    // Split a token sequence into batches
    std::vector<TokenBatch> SplitBatch(const std::vector<int32_t>& tokens, size_t start_pos = 0) {
        std::vector<TokenBatch> batches;
        
        if (!initialized_ || tokens.empty()) {
            return batches;
        }
        
        size_t pos = 0;
        while (pos < tokens.size()) {
            TokenBatch batch;
            
            // Calculate batch size
            size_t batch_size = config_.max_batch_size;
            if (pos + batch_size > tokens.size()) {
                batch_size = tokens.size() - pos;
            }
            
            // Copy tokens
            batch.tokens.reserve(batch_size);
            for (size_t i = 0; i < batch_size; i++) {
                batch.tokens.push_back(tokens[pos + i]);
            }
            
            // Calculate positions
            batch.position_offset = start_pos + pos;
            batch.positions.reserve(batch_size);
            for (size_t i = 0; i < batch_size; i++) {
                batch.positions.push_back(static_cast<int32_t>(batch.position_offset + i));
            }
            
            batches.push_back(batch);
            
            // Advance position (with overlap if enabled)
            if (config_.enable_overlap && config_.overlap_tokens > 0 && pos + batch_size < tokens.size()) {
                pos += (batch_size - config_.overlap_tokens);
            } else {
                pos += batch_size;
            }
        }
        
        return batches;
    }
    
    bool IsInitialized() const { return initialized_; }
    const SplitterConfig& GetConfig() const { return config_; }
    
private:
    bool initialized_;
    SplitterConfig config_;
};

} // namespace Sovereign

#endif // SOVEREIGN_BATCH_SPLITTER_HPP
