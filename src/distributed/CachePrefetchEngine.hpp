// RawrXD Cache Prefetch Engine
// Phase O.4: Intelligent prefetching for distributed KV cache
// Predicts and preloads cache entries before they're needed

#pragma once

#include <vector>
#include <map>
#include <queue>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <random>

namespace RawrXD {
namespace Distributed {

// Forward declarations
class DistributedKVCache;

// Access pattern types
enum class AccessPattern {
    SEQUENTIAL,     // Linear sequence (tokens 1,2,3...)
    STRIDED,        // Fixed stride (tokens 1,3,5...)
    RANDOM,         // No predictable pattern
    BURST,          // Bursty access
    TEMPORAL        // Time-based locality
};

// Prefetch prediction
struct PrefetchPrediction {
    std::vector<std::string> keysToPrefetch;
    float confidence;
    AccessPattern predictedPattern;
    uint32_t lookaheadDistance;
    
    // Timing
    std::chrono::steady_clock::time_point predictedAt;
    std::chrono::milliseconds predictedAccessTime;
};

// Prefetch request
struct PrefetchRequest {
    std::string sessionId;
    std::string modelId;
    uint32_t currentPosition;
    uint32_t lookaheadCount;
    
    // Context
    std::vector<std::string> recentAccesses;
    uint32_t sequenceLength;
};

// Prefetch result
struct PrefetchResult {
    bool success;
    uint32_t keysPrefetched;
    uint32_t keysAlreadyCached;
    uint32_t keysFailed;
    
    // Performance
    std::chrono::milliseconds prefetchTime;
    size_t bytesPrefetched;
    
    // Accuracy (measured later)
    float hitRate;
    uint32_t hits;
    uint32_t misses;
};

// Pattern detector configuration
struct PatternConfig {
    // Window sizes
    uint32_t historyWindowSize = 100;
    uint32_t minPatternLength = 3;
    uint32_t maxPatternLength = 50;
    
    // Confidence thresholds
    float sequentialThreshold = 0.8f;
    float stridedThreshold = 0.7f;
    float temporalThreshold = 0.6f;
    
    // Prefetch distances
    uint32_t sequentialPrefetchDistance = 128;
    uint32_t stridedPrefetchDistance = 64;
    uint32_t temporalPrefetchDistance = 32;
    
    // Adaptive
    bool enableAdaptivePrefetch = true;
    uint32_t minPrefetchDistance = 16;
    uint32_t maxPrefetchDistance = 256;
    float hitRateTarget = 0.9f;
};

// Access history entry
struct AccessHistoryEntry {
    std::string key;
    std::chrono::steady_clock::time_point timestamp;
    uint32_t position;
    bool wasHit;
};

// Pattern detector
class PatternDetector {
public:
    PatternDetector(const PatternConfig& config);
    
    // Record access
    void recordAccess(const std::string& key, uint32_t position, bool wasHit);
    void recordBatch(const std::vector<AccessHistoryEntry>& accesses);
    
    // Pattern detection
    AccessPattern detectPattern(const std::string& sessionId) const;
    std::vector<uint32_t> predictNextPositions(const std::string& sessionId, 
                                                  uint32_t count) const;
    
    // Confidence scoring
    float getPatternConfidence(const std::string& sessionId) const;
    void resetSession(const std::string& sessionId);
    void clear();
    
    // Statistics
    struct DetectionStats {
        uint64_t totalAccesses;
        uint64_t sequentialDetections;
        uint64_t stridedDetections;
        uint64_t randomDetections;
        uint64_t temporalDetections;
        double avgConfidence;
    };
    DetectionStats getStats() const;
    
private:
    // Pattern detection methods
    bool isSequential(const std::vector<uint32_t>& positions) const;
    bool isStrided(const std::vector<uint32_t>& positions, uint32_t& stride) const;
    bool isTemporal(const std::vector<std::chrono::steady_clock::time_point>& timestamps) const;
    
    PatternConfig config_;
    std::map<std::string, std::vector<AccessHistoryEntry>> sessionHistory_;
    mutable std::mutex mutex_;
};

// Prefetch engine configuration
struct PrefetchEngineConfig {
    // Threading
    uint32_t prefetchThreads = 4;
    uint32_t maxConcurrentPrefetches = 10;
    
    // Throttling
    bool enableThrottling = true;
    uint32_t maxPrefetchBandwidthMBps = 1000;
    float cpuUsageThreshold = 0.8f;
    float memoryPressureThreshold = 0.9f;
    
    // Prioritization
    bool prioritizeSequential = true;
    bool prioritizeActiveSessions = true;
    uint32_t activeSessionWindowSeconds = 60;
    
    // Feedback
    bool enableFeedbackLoop = true;
    uint32_t feedbackWindowSize = 100;
    float accuracyThreshold = 0.7f;
};

// Prefetch engine
class CachePrefetchEngine {
public:
    CachePrefetchEngine(std::shared_ptr<DistributedKVCache> cache);
    ~CachePrefetchEngine();
    
    // Initialization
    bool initialize(const PrefetchEngineConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Pattern detection
    void recordAccess(const std::string& sessionId, const std::string& key, 
                      uint32_t position, bool wasHit);
    void recordBatch(const std::string& sessionId, 
                     const std::vector<AccessHistoryEntry>& accesses);
    
    // Prefetching
    PrefetchResult prefetch(const PrefetchRequest& request);
    bool prefetchSequential(const std::string& sessionId, const std::string& modelId,
                            uint32_t startPosition, uint32_t count);
    bool prefetchStrided(const std::string& sessionId, const std::string& modelId,
                         uint32_t startPosition, uint32_t stride, uint32_t count);
    bool prefetchTemporal(const std::string& sessionId, 
                          const std::vector<std::string>& recentKeys);
    
    // Adaptive prefetching
    void adjustPrefetchDistance(const std::string& sessionId, float hitRate);
    uint32_t getOptimalPrefetchDistance(const std::string& sessionId) const;
    
    // Session management
    void registerSession(const std::string& sessionId, const std::string& modelId);
    void unregisterSession(const std::string& sessionId);
    std::vector<std::string> getActiveSessions() const;
    
    // Throttling
    bool shouldThrottle() const;
    void setBandwidthLimit(uint32_t mbps);
    
    // Statistics
    struct PrefetchStats {
        uint64_t totalPrefetches;
        uint64_t successfulPrefetches;
        uint64_t failedPrefetches;
        uint64_t cancelledPrefetches;
        
        uint64_t totalKeysPrefetched;
        uint64_t keysHit;
        uint64_t keysMissed;
        double prefetchHitRate;
        
        double avgPrefetchTimeMs;
        double avgPrefetchDistance;
        size_t totalBytesPrefetched;
        
        std::map<std::string, double> hitRateBySession;
        std::map<AccessPattern, uint64_t> prefetchesByPattern;
    };
    PrefetchStats getStats() const;
    void resetStats();
    
    // Configuration
    PrefetchEngineConfig getConfig() const { return config_; }
    bool updateConfig(const PrefetchEngineConfig& config);
    
private:
    // Internal methods
    void prefetchLoop();
    void feedbackLoop();
    
    std::vector<std::string> generatePrefetchKeys(const PrefetchRequest& request);
    bool executePrefetch(const std::vector<std::string>& keys);
    void updateHitRateStats(const std::string& sessionId, bool wasHit);
    
    // Threading
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::thread prefetchThread_;
    std::thread feedbackThread_;
    mutable std::mutex mutex_;
    
    // Components
    std::unique_ptr<PatternDetector> patternDetector_;
    std::shared_ptr<DistributedKVCache> cache_;
    
    // State
    PrefetchEngineConfig config_;
    std::map<std::string, uint32_t> sessionPrefetchDistance_;
    std::map<std::string, std::chrono::steady_clock::time_point> sessionLastAccess_;
    std::queue<PrefetchRequest> prefetchQueue_;
    
    // Feedback tracking
    std::map<std::string, std::vector<bool>> prefetchAccuracy_;
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> totalPrefetches{0};
        std::atomic<uint64_t> successfulPrefetches{0};
        std::atomic<uint64_t> failedPrefetches{0};
        std::atomic<uint64_t> cancelledPrefetches{0};
        std::atomic<uint64_t> totalKeysPrefetched{0};
        std::atomic<uint64_t> keysHit{0};
        std::atomic<uint64_t> keysMissed{0};
        std::atomic<double> totalPrefetchTimeMs{0.0};
        std::atomic<size_t> totalBytesPrefetched{0};
    } stats_;
};

// Smart prefetcher with ML-based prediction (placeholder for future)
class SmartPrefetcher {
public:
    SmartPrefetcher(CachePrefetchEngine* engine);
    
    // ML-based prediction
    std::vector<std::string> predictAccesses(const std::string& sessionId,
                                              const std::vector<std::string>& context);
    
    // Model training
    void train(const std::vector<AccessHistoryEntry>& trainingData);
    void updateModel(const AccessHistoryEntry& access);
    
private:
    CachePrefetchEngine* engine_;
    // Would contain ML model
};

} // namespace Distributed
} // namespace RawrXD
