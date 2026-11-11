// ============================================================================
// SlidingWindowEngine.h - Sliding Context Window for Long Sequences
//
// VAL-000 Component: Memory Engine → Sliding Tensor Windows
//
// Implements a sliding window over the KV cache and attention computation,
// enabling efficient processing of sequences longer than maxSeqLen.
//
// Key features:
//   - Sliding attention window (configurable size)
//   - Position-rotated KV cache (old entries evicted as new ones arrive)
//   - Chunked prefill for long prompts
//   - Overlap region preservation for context continuity
//   - Dynamic window sizing based on attention entropy
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 2
// ============================================================================

#ifndef DEEP2_SLIDING_WINDOW_ENGINE_H
#define DEEP2_SLIDING_WINDOW_ENGINE_H

#include <cstddef>
#include <cstdint>
#include <vector>
#include <cmath>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Sliding window configuration
// ---------------------------------------------------------------------------
struct SlidingWindowConfig {
    size_t windowSize = 4096;         // Active attention window
    size_t overlapSize = 512;         // Overlap between windows
    size_t chunkSize = 2048;          // Prefill chunk size
    bool   dynamicWindow = true;      // Adapt window based on entropy
    float  minWindowSize = 1024;      // Minimum window when shrinking
    float  maxWindowSize = 32768;     // Maximum window when growing
    float  entropyThreshold = 2.0f;   // Bits/token threshold for growing
};

// ---------------------------------------------------------------------------
// SlidingWindowEngine - Manages sliding context for long sequences
// ---------------------------------------------------------------------------
class SlidingWindowEngine {
public:
    SlidingWindowEngine();
    ~SlidingWindowEngine();
    
    // Initialize
    bool initialize(const SlidingWindowConfig& config);
    
    // Process a new token through the sliding window
    // Returns the effective position for attention
    size_t processToken(size_t globalPos);
    
    // Get the attention range [start, end) for current position
    void getAttentionRange(size_t& start, size_t& end) const;
    
    // Chunk a long prompt into processing windows
    std::vector<std::pair<size_t, size_t>> chunkPrompt(size_t promptLen) const;
    
    // Update window size based on attention entropy
    void adaptWindow(float entropy);
    
    // Get current window size
    size_t getWindowSize() const { return currentWindowSize; }
    size_t getEffectiveSeqLen() const { return effectiveSeqLen; }
    
    // Check if position is in the active window
    bool isInWindow(size_t pos) const;
    
    // Get positions to evict (outside window)
    std::vector<size_t> getEvictionCandidates() const;
    
    // Reset for new sequence
    void reset();
    
private:
    SlidingWindowConfig config;
    size_t currentWindowSize;
    size_t effectiveSeqLen;
    size_t windowStart;
    size_t windowEnd;
    
    // Entropy tracking for dynamic window
    std::vector<float> entropyHistory;
    float avgEntropy;
    
    void updateWindow();
};

} // namespace Deep2

#endif // DEEP2_SLIDING_WINDOW_ENGINE_H
