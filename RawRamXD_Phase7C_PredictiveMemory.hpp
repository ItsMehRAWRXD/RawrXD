// =============================================================================
// RawRamXD_Phase7C_PredictiveMemory.hpp
// Predictive Memory Intelligence - Learning-Based Policy Refinement
// =============================================================================
// Phase 7C: Predictive Memory Intelligence
// Goal: Turn RawRamXD's telemetry + autonomous placement into a learning
//       system that refines its own policies over time.
//
// Core Components:
// - SequenceLogger: Persist per-tensor access traces
// - PatternMiner: Detect recurring patterns -> "placement profiles"
// - PolicyRefinementEngine: Feed profiles back into solver
// - OnlineAdaptationController: Adjust aggression based on live workload class
// =============================================================================

#ifndef RAWRAMXD_PHASE7C_PREDICTIVE_MEMORY_HPP
#define RAWRAMXD_PHASE7C_PREDICTIVE_MEMORY_HPP

#include <stdint.h>
#include <vector>
#include <string>
#include <memory>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <fstream>
#include <sstream>
#include <queue>
#include <deque>
#include <algorithm>
#include <array>
#include <thread>
#include <random>
#include <functional>

namespace RawRamXD {

// =============================================================================
// Phase 7C: Sequence Logger - Persist Per-Tensor Access Traces
// =============================================================================

enum class AccessType : uint8_t {
    READ = 0,
    WRITE = 1,
    READ_WRITE = 2,
    PREFETCH = 3,
    EVICT = 4,
    MIGRATE = 5
};

enum class MemoryTier : uint8_t {
    HOST = 0,
    GPU0 = 1,
    GPU1 = 2,
    GPU2 = 3,
    GPU3 = 4,
    NVME = 5,
    REMOTE = 6
};

// Single access event in a tensor's lifetime
struct TensorAccessEvent {
    uint64_t timestampUs;           // Microsecond timestamp
    uint64_t tensorId;              // Unique tensor identifier
    AccessType accessType;          // Type of access
    MemoryTier sourceTier;          // Where tensor was before
    MemoryTier targetTier;          // Where tensor is after
    uint64_t offset;                // Offset within tensor
    uint64_t sizeBytes;             // Size of access
    uint32_t computeNode;           // Which compute unit accessed
    uint32_t latencyUs;             // Observed latency
    bool wasHit;                    // Was this a cache hit?
    
    // Serialize to binary
    void Serialize(std::ofstream& out) const;
    bool Deserialize(std::ifstream& in);
};

// Complete access trace for a single tensor
struct SequenceTrace {
    uint64_t tensorId = 0;
    uint64_t firstSeenUs = 0;
    uint64_t lastAccessUs = 0;
    std::vector<TensorAccessEvent> events;
    uint64_t totalReads = 0;
    uint64_t totalWrites = 0;
    uint64_t totalBytesTransferred = 0;
    uint32_t uniqueTiersVisited = 0;
    
    SequenceTrace() = default;
    void AddEvent(const TensorAccessEvent& event);
    double GetAverageAccessIntervalUs() const;
    double GetAccessFrequencyHz() const;
    MemoryTier GetPreferredTier() const;  // Tier with most hits
};

// Persistent sequence logger
class SequenceLogger {
public:
    static constexpr size_t MAX_TRACE_HISTORY = 100000;
    static constexpr size_t FLUSH_INTERVAL_MS = 5000;
    
    bool Initialize(const std::string& logDir);
    void Shutdown();
    
    // Log an access event
    void LogEvent(const TensorAccessEvent& event);
    
    // Get trace for specific tensor
    std::shared_ptr<SequenceTrace> GetTrace(uint64_t tensorId);
    
    // Get all traces
    std::vector<std::shared_ptr<SequenceTrace>> GetAllTraces();
    
    // Persist traces to disk
    bool FlushToDisk();
    
    // Load historical traces
    bool LoadFromDisk(const std::string& filename);
    
    // Clear all traces
    void Clear();
    
    // Get statistics
    struct LoggerStats {
        uint64_t totalEventsLogged;
        uint64_t totalTraces;
        uint64_t eventsInMemory;
        uint64_t lastFlushTime;
        size_t memoryUsageBytes;
    };
    LoggerStats GetStats() const;

private:
    std::unordered_map<uint64_t, std::shared_ptr<SequenceTrace>> traces_;
    std::deque<TensorAccessEvent> pendingEvents_;
    mutable std::mutex mutex_;
    std::string logDir_;
    std::atomic<uint64_t> totalEventsLogged_{0};
    std::atomic<uint64_t> lastFlushTime_{0};
    
    void BackgroundFlush();
};

// =============================================================================
// Phase 7C: Pattern Miner - Detect Recurring Patterns
// =============================================================================

// Workload characteristics signature
struct WorkloadSignature {
    double readWriteRatio;
    double sequentiality;           // 0=random, 1=fully sequential
    double temporalLocality;         // Reuse within time window
    double spatialLocality;          // Nearby address access
    double burstiness;               // Access pattern burstiness
    uint64_t avgTensorLifetimeMs;
    uint64_t avgAccessIntervalUs;
    uint32_t uniqueTensorCount;
    
    // Compute hash for signature
    uint64_t Hash() const;
    bool operator==(const WorkloadSignature& other) const;
};

// Placement profile derived from historical traces
struct PlacementProfile {
    uint64_t profileId;
    WorkloadSignature signature;
    
    // Optimal placement strategy for this workload type
    struct TierPreference {
        MemoryTier tier;
        double affinityScore;        // 0-1, how well this tier fits
        double expectedHitRate;
        uint64_t avgLatencyUs;
    };
    std::vector<TierPreference> tierPreferences;
    
    // Prefetch strategy
    double prefetchThreshold;        // Confidence threshold for prefetch
    uint64_t prefetchDistance;     // How far ahead to prefetch
    
    // Eviction strategy
    double evictionAggression;       // 0=conservative, 1=aggressive
    uint64_t evictionWindowMs;     // Time window for LRU
    
    // Migration strategy
    double migrationThreshold;       // When to trigger migration
    uint64_t migrationCooldownMs;  // Minimum time between migrations
    
    // Validation metrics
    uint64_t timesApplied;
    double cumulativeHitRate;
    double cumulativeLatency;
    uint64_t lastUpdated;
};

// Discovered access pattern
struct AccessPattern {
    enum class PatternType {
        SEQUENTIAL,      // Linear access pattern
        STRIDED,         // Fixed stride between accesses
        RANDOM,          // No discernible pattern
        REPEATING,       // Same offsets accessed repeatedly
        TEMPORAL,        // Time-based access clusters
        BLOCKED,         // Block/chunk-based access
        HYBRID           // Mixed pattern
    } type;
    
    std::vector<uint64_t> offsetSequence;
    uint64_t stride;                 // For strided patterns
    uint64_t blockSize;              // For blocked patterns
    double confidence;
    uint64_t occurrences;
};

class PatternMiner {
public:
    static constexpr size_t MIN_PATTERN_LENGTH = 3;
    static constexpr double MIN_CONFIDENCE = 0.75;
    static constexpr uint64_t PATTERN_EXPIRY_MS = 3600000; // 1 hour
    
    bool Initialize();
    void Shutdown();
    
    // Mine patterns from sequence traces
    std::vector<AccessPattern> MinePatterns(const SequenceTrace& trace);
    
    // Generate placement profile from workload signature
    PlacementProfile GenerateProfile(const WorkloadSignature& signature);
    
    // Update existing profile with new observations
    void UpdateProfile(PlacementProfile& profile, const SequenceTrace& trace, double hitRate);
    
    // Find matching profile for workload
    std::shared_ptr<PlacementProfile> FindMatchingProfile(const WorkloadSignature& signature);
    
    // Store and retrieve profiles
    void StoreProfile(const PlacementProfile& profile);
    std::shared_ptr<PlacementProfile> GetProfile(uint64_t profileId);
    std::vector<std::shared_ptr<PlacementProfile>> GetAllProfiles();
    
    // Compute workload signature from traces
    WorkloadSignature ComputeSignature(const std::vector<std::shared_ptr<SequenceTrace>>& traces);
    
    // Pattern persistence
    bool SaveProfiles(const std::string& filename);
    bool LoadProfiles(const std::string& filename);
    
    // Statistics
    struct MinerStats {
        uint64_t patternsDiscovered;
        uint64_t profilesGenerated;
        uint64_t profileMatches;
        uint64_t profileMisses;
        double averageMatchConfidence;
    };
    MinerStats GetStats() const;

private:
    std::unordered_map<uint64_t, std::shared_ptr<PlacementProfile>> profiles_;
    std::unordered_map<uint64_t, AccessPattern> patterns_;
    mutable std::mutex mutex_;
    
    MinerStats stats_;
    
    // Pattern detection algorithms
    AccessPattern DetectSequentialPattern(const SequenceTrace& trace);
    AccessPattern DetectStridedPattern(const SequenceTrace& trace);
    AccessPattern DetectRepeatingPattern(const SequenceTrace& trace);
    AccessPattern DetectTemporalPattern(const SequenceTrace& trace);
    
    // Similarity calculation
    double ComputeSignatureSimilarity(const WorkloadSignature& a, const WorkloadSignature& b);
};

// =============================================================================
// Phase 7C: Policy Refinement Engine - Feed Profiles Back Into Solver
// =============================================================================

// Feedback from policy application
struct PolicyFeedback {
    uint64_t profileId;
    uint64_t timestamp;
    double actualHitRate;
    double predictedHitRate;
    double actualLatencyUs;
    double predictedLatencyUs;
    uint64_t bytesTransferred;
    uint64_t migrationCount;
    uint64_t evictionCount;
    double throughput;
    bool wasBeneficial;              // Did this policy help?
};

// Refined policy after learning
struct RefinedPolicy {
    uint64_t baseProfileId;
    uint64_t refinementVersion;
    uint64_t lastRefined;
    
    // Adjusted parameters
    double adjustedPrefetchThreshold;
    double adjustedEvictionAggression;
    double adjustedMigrationThreshold;
    uint64_t migrationCooldownMs;
    
    // Performance deltas
    double hitRateImprovement;
    double latencyReduction;
    double throughputGain;
    
    // Confidence in refinement
    double refinementConfidence;
    uint64_t observationsCount;
};

class PolicyRefinementEngine {
public:
    static constexpr double LEARNING_RATE = 0.1;
    static constexpr size_t MIN_OBSERVATIONS = 10;
    static constexpr double IMPROVEMENT_THRESHOLD = 0.05; // 5% improvement
    
    bool Initialize(PatternMiner* miner);
    void Shutdown();
    
    // Record feedback from policy application
    void RecordFeedback(const PolicyFeedback& feedback);
    
    // Refine policies based on accumulated feedback
    void RefinePolicies();
    
    // Get refined policy for profile
    std::shared_ptr<RefinedPolicy> GetRefinedPolicy(uint64_t profileId);
    
    // Apply refinement to placement profile
    bool ApplyRefinement(PlacementProfile& profile, const RefinedPolicy& refinement);
    
    // Predict performance for policy
    struct PerformancePrediction {
        double predictedHitRate;
        double predictedLatencyUs;
        double predictedThroughput;
        double confidence;
    };
    PerformancePrediction PredictPerformance(uint64_t profileId);
    
    // Statistics
    struct RefinementStats {
        uint64_t feedbacksRecorded;
        uint64_t policiesRefined;
        uint64_t successfulRefinements;
        double averageImprovement;
        uint64_t lastRefinementTime;
    };
    RefinementStats GetStats() const;
    
    // Persistence
    bool SaveRefinements(const std::string& filename);
    bool LoadRefinements(const std::string& filename);

private:
    PatternMiner* miner_;
    std::unordered_map<uint64_t, std::vector<PolicyFeedback>> feedbackHistory_;
    std::unordered_map<uint64_t, std::shared_ptr<RefinedPolicy>> refinedPolicies_;
    mutable std::mutex mutex_;
    
    RefinementStats stats_;
    
    // Refinement algorithms
    RefinedPolicy ComputeRefinement(uint64_t profileId, const std::vector<PolicyFeedback>& feedback);
    double CalculateImprovement(const std::vector<PolicyFeedback>& feedback);
};

// =============================================================================
// Phase 7C: Online Adaptation Controller - Live Workload Classification
// =============================================================================

enum class WorkloadClass : uint8_t {
    INFERENCE_SMALL = 0,     // Small model inference
    INFERENCE_LARGE = 1,     // Large model inference
    TRAINING_SMALL = 2,      // Small model training
    TRAINING_LARGE = 3,      // Large model training
    EMBEDDING_LOOKUP = 4,    // Embedding-heavy workload
    ATTENTION_COMPUTE = 5,   // Attention-heavy workload
    MIXED = 6,               // Mixed workload type
    UNKNOWN = 7              // Not yet classified
};

// Aggression level for memory policies
enum class AggressionLevel : uint8_t {
    CONSERVATIVE = 0,        // Minimize migrations, maximize stability
    MODERATE = 1,            // Balanced approach
    AGGRESSIVE = 2,          // Maximize performance, accept more migrations
    ADAPTIVE = 3             // Dynamically adjust based on feedback
};

// Policy parameters for memory management
struct PolicyParameters {
    double prefetchThreshold;
    double evictionAggression;
    double migrationThreshold;
    uint64_t migrationCooldownMs;
    bool enableProactivePlacement;
};

// Live workload state
struct WorkloadState {
    WorkloadClass currentClass;
    WorkloadSignature currentSignature;
    AggressionLevel aggressionLevel;
    uint64_t classificationTime;
    double confidence;
    
    // Runtime metrics
    double currentHitRate;
    double currentLatency;
    double currentThroughput;
    double memoryPressure;
};

class OnlineAdaptationController {
public:
    static constexpr uint64_t CLASSIFICATION_WINDOW_MS = 1000;
    static constexpr double CLASSIFICATION_CONFIDENCE_THRESHOLD = 0.7;
    
    bool Initialize(PatternMiner* miner, PolicyRefinementEngine* engine);
    void Shutdown();
    
    // Classify current workload based on recent traces
    WorkloadClass ClassifyWorkload(const std::vector<std::shared_ptr<SequenceTrace>>& recentTraces);
    
    // Update aggression level based on performance
    void UpdateAggression(const WorkloadState& state);
    
    // Get current aggression level
    AggressionLevel GetAggressionLevel() const { return currentAggression_; }
    
    // Get recommended policy parameters for current state
    PolicyParameters GetPolicyParameters() const;
    
    // Handle workload transition
    void OnWorkloadTransition(WorkloadClass oldClass, WorkloadClass newClass);
    
    // Get current workload state
    WorkloadState GetCurrentState() const;
    
    // Statistics
    struct AdaptationStats {
        uint64_t classificationsPerformed;
        uint64_t aggressionChanges;
        uint64_t workloadTransitions;
        std::unordered_map<WorkloadClass, uint64_t> classDistribution;
        double averageClassificationConfidence;
    };
    AdaptationStats GetStats() const;

private:
    PatternMiner* miner_;
    PolicyRefinementEngine* engine_;
    
    WorkloadState currentState_;
    AggressionLevel currentAggression_;
    mutable std::mutex mutex_;
    
    AdaptationStats stats_;
    
    // Classification logic
    WorkloadClass ClassifyBySignature(const WorkloadSignature& sig);
    double ComputeClassConfidence(WorkloadClass cls, const WorkloadSignature& sig);
    
    // Aggression adjustment
    void AdjustAggressionUp();
    void AdjustAggressionDown();
};

// =============================================================================
// Phase 7C: Predictive Memory Intelligence Controller
// =============================================================================

struct PredictiveIntelligenceConfig {
    bool enableSequenceLogging;
    bool enablePatternMining;
    bool enablePolicyRefinement;
    bool enableOnlineAdaptation;
    std::string persistenceDir;
    uint64_t refinementIntervalMs;
    uint64_t adaptationIntervalMs;
};

class PredictiveMemoryIntelligence {
public:
    static PredictiveMemoryIntelligence& Instance();
    
    bool Initialize(const PredictiveIntelligenceConfig& config);
    void Shutdown();
    
    // Core integration points
    void OnTensorAccess(const TensorAccessEvent& event);
    void OnInferenceStart(uint64_t modelId);
    void OnInferenceEnd(uint64_t modelId, const WorkloadSignature& signature);
    
    // Query learned policies
    std::shared_ptr<PlacementProfile> GetPolicyForWorkload(const WorkloadSignature& signature);
    PolicyParameters GetCurrentPolicyParameters();
    
    // Force policy refinement
    void TriggerPolicyRefinement();
    
    // Get current workload classification
    WorkloadClass GetCurrentWorkloadClass() const;
    
    // Reporting
    bool GenerateIntelligenceReport(const std::string& filename);
    
    // Metrics
    struct IntelligenceMetrics {
        uint64_t eventsLogged;
        uint64_t patternsMined;
        uint64_t policiesRefined;
        uint64_t workloadClassifications;
        double currentHitRate;
        double policyEffectiveness;
        uint64_t memorySavedBytes;
    };
    IntelligenceMetrics GetMetrics() const;

private:
    PredictiveMemoryIntelligence() = default;
    ~PredictiveMemoryIntelligence() = default;
    
    std::unique_ptr<SequenceLogger> sequenceLogger_;
    std::unique_ptr<PatternMiner> patternMiner_;
    std::unique_ptr<PolicyRefinementEngine> refinementEngine_;
    std::unique_ptr<OnlineAdaptationController> adaptationController_;
    
    PredictiveIntelligenceConfig config_;
    mutable std::mutex mutex_;
    
    void BackgroundRefinement();
    void BackgroundAdaptation();
};

// =============================================================================
// Phase 7C: C API for External Integration
// =============================================================================

extern "C" {

// Initialize predictive intelligence
bool RawRamXD_PredictiveIntelligence_Initialize(const char* persistenceDir);
void RawRamXD_PredictiveIntelligence_Shutdown();

// Log access event
void RawRamXD_LogAccessEvent(uint64_t tensorId, int accessType, 
                              int sourceTier, int targetTier,
                              uint64_t offset, uint64_t size,
                              uint32_t latencyUs, int wasHit);

// Get policy for current workload
int RawRamXD_GetRecommendedTier(uint64_t tensorId, uint64_t* predictedHitRate);

// Get current aggression level
int RawRamXD_GetAggressionLevel();

// Trigger manual refinement
void RawRamXD_TriggerPolicyRefinement();

// Get workload classification
int RawRamXD_GetCurrentWorkloadClass();

// Generate report
bool RawRamXD_SaveIntelligenceReport(const char* filename);

} // extern "C"

} // namespace RawRamXD

#endif // RAWRAMXD_PHASE7C_PREDICTIVE_MEMORY_HPP