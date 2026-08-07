// ============================================================================
// SlidingWindowEngine.cpp - Implementation
// ============================================================================

#include "SlidingWindowEngine.h"
#include <algorithm>
#include <cstdio>

namespace Deep2 {

SlidingWindowEngine::SlidingWindowEngine()
    : currentWindowSize(4096), effectiveSeqLen(0),
      windowStart(0), windowEnd(0), avgEntropy(0.0f) {}

SlidingWindowEngine::~SlidingWindowEngine() {}

bool SlidingWindowEngine::initialize(const SlidingWindowConfig& cfg) {
    config = cfg;
    currentWindowSize = cfg.windowSize;
    effectiveSeqLen = 0;
    windowStart = 0;
    windowEnd = 0;
    entropyHistory.clear();
    avgEntropy = 0.0f;
    
    printf("[SlidingWindow] Initialized: window=%zu, overlap=%zu, chunk=%zu\n",
           cfg.windowSize, cfg.overlapSize, cfg.chunkSize);
    return true;
}

size_t SlidingWindowEngine::processToken(size_t globalPos) {
    effectiveSeqLen = globalPos + 1;
    updateWindow();
    return globalPos - windowStart;
}

void SlidingWindowEngine::getAttentionRange(size_t& start, size_t& end) const {
    start = windowStart;
    end = std::min(windowEnd, effectiveSeqLen);
}

std::vector<std::pair<size_t, size_t>> SlidingWindowEngine::chunkPrompt(
    size_t promptLen) const {
    std::vector<std::pair<size_t, size_t>> chunks;
    
    if (promptLen <= config.chunkSize) {
        chunks.push_back({0, promptLen});
        return chunks;
    }
    
    size_t pos = 0;
    while (pos < promptLen) {
        size_t end = std::min(pos + config.chunkSize, promptLen);
        chunks.push_back({pos, end});
        
        // Move forward with overlap
        if (end >= promptLen) break;
        pos = end - config.overlapSize;
        if (pos <= chunks.back().first) pos = end;  // Ensure progress
    }
    
    return chunks;
}

void SlidingWindowEngine::adaptWindow(float entropy) {
    if (!config.dynamicWindow) return;
    
    // Track entropy history
    entropyHistory.push_back(entropy);
    if (entropyHistory.size() > 100) entropyHistory.erase(entropyHistory.begin());
    
    // Compute moving average
    float sum = 0.0f;
    for (float e : entropyHistory) sum += e;
    avgEntropy = sum / entropyHistory.size();
    
    // Grow window if entropy is high (more context needed)
    if (avgEntropy > config.entropyThreshold) {
        currentWindowSize = std::min((size_t)(currentWindowSize * 1.25),
                                      (size_t)config.maxWindowSize);
    }
    // Shrink window if entropy is low (less context needed)
    else if (avgEntropy < config.entropyThreshold * 0.5) {
        currentWindowSize = std::max((size_t)(currentWindowSize * 0.75),
                                      (size_t)config.minWindowSize);
    }
}

bool SlidingWindowEngine::isInWindow(size_t pos) const {
    return pos >= windowStart && pos < windowEnd;
}

std::vector<size_t> SlidingWindowEngine::getEvictionCandidates() const {
    std::vector<size_t> candidates;
    // Positions before windowStart can be evicted
    for (size_t i = 0; i < windowStart; ++i) {
        candidates.push_back(i);
    }
    return candidates;
}

void SlidingWindowEngine::updateWindow() {
    if (effectiveSeqLen <= currentWindowSize) {
        windowStart = 0;
        windowEnd = effectiveSeqLen;
    } else {
        windowEnd = effectiveSeqLen;
        windowStart = windowEnd - currentWindowSize;
    }
}

void SlidingWindowEngine::reset() {
    effectiveSeqLen = 0;
    windowStart = 0;
    windowEnd = 0;
    entropyHistory.clear();
    avgEntropy = 0.0f;
    currentWindowSize = config.windowSize;
}

} // namespace Deep2
