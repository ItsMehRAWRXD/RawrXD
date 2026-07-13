// RawrXD Auto-Tuning Engine
// Phase P.4: Automatic performance tuning with ML-based optimization
// Self-optimizing inference parameters based on workload patterns

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

namespace RawrXD {
namespace Performance {

// Forward declarations
class PerformanceProfiler;
class BottleneckAnalyzer;
class AlertManager;

// Tuning parameter types
enum class TuningParameter {
    BATCH_SIZE,           // Inference batch size
    THREAD_COUNT,         // Number of worker threads
    GPU_MEMORY_FRACTION,  // GPU memory allocation
    KV_CACHE_SIZE,        // KV cache size
    ATTENTION_HEADS,      // Number of attention heads
    QUANTIZATION_BITS,    // Quantization level
    STREAMING_CHUNK_SIZE, // Streaming chunk size
    PREFETCH_DISTANCE,    // Prefetch distance
    SCHEDULER_PRIORITY,   // Task scheduler priority
    WORKER_AFFINITY       // CPU affinity mask
};

// Tuning strategy
enum class TuningStrategy {
    GRADIENT_DESCENT,     // Gradient-based optimization
    BAYESIAN,             // Bayesian optimization
    GENETIC,              // Genetic algorithm
    REINFORCEMENT_LEARNING, // RL-based tuning
    RULE_BASED          // Rule-based heuristics
};

// Tuning target
struct TuningTarget {
    float targetLatencyMs = 100.0f;
    float targetThroughput = 1000.0f;
    float targetErrorRate = 0.01f;
    float targetMemoryUtilization = 0.8f;
    float targetGpuUtilization = 0.85f;
    
    // Weights for multi-objective optimization
    float latencyWeight = 0.3f;
    float throughputWeight = 0.3f;
    float errorWeight = 0.2f;
    float resourceWeight = 0.2f;
};

// Tuning constraints
struct TuningConstraints {
    // Resource limits
    uint32_t maxBatchSize = 64;
    uint32_t maxThreadCount = 32;
    float maxGpuMemoryFraction = 0.95f;
    uint64_t maxKvCacheSize = 8ULL * 1024 * 1024 * 1024; // 8GB
    
    // Performance limits
    float maxLatencyMs = 500.0f;
    float minThroughput = 100.0f;
    float maxErrorRate = 0.05f;
    
    // Safety
    bool requireApproval = true;
    bool dryRun = false;
    uint32_t maxAdjustmentsPerHour = 6;
    float maxAdjustmentPercent = 0.25f;  // Max 25% change per adjustment
};

// Auto-tuning configuration
struct AutoTuningConfig {
    bool enabled = false;
    TuningStrategy strategy = TuningStrategy::BAYESIAN;
    
    // Timing
    uint32_t tuningIntervalMinutes = 10;
    uint32_t measurementWindowMinutes = 5;
    uint32_t stabilizationMinutes = 5;
    
    // Targets and constraints
    TuningTarget target;
    TuningConstraints constraints;
    
    // Rollback
    bool autoRollback = true;
    float rollbackThreshold = 0.20f;  // Rollback if performance degrades >20%
    uint32_t rollbackWindowMinutes = 30;
    
    // Learning
    bool persistentLearning = true;
    std::string modelPath;  // Path to save/load learned models
    
    // Parameters to tune
    std::vector<TuningParameter> parametersToTune = {
        TuningParameter::BATCH_SIZE,
        TuningParameter::THREAD_COUNT,
        TuningParameter::KV_CACHE_SIZE,
        TuningParameter::STREAMING_CHUNK_SIZE
    };
};

// Tuning adjustment
struct TuningAdjustment {
    std::string id;
    TuningParameter parameter;
    double oldValue;
    double newValue;
    std::string reason;
    std::chrono::steady_clock::time_point proposedAt;
    std::chrono::steady_clock::time_point appliedAt;
    std::chrono::steady_clock::time_point evaluatedAt;
    
    // Status
    enum class Status {
        PENDING_APPROVAL,
        APPROVED,
        REJECTED,
        APPLIED,
        EVALUATING,
        SUCCESS,
        ROLLED_BACK
    } status;
    
    // Results
    double measuredImprovement;
    double confidence;
    std::string rollbackReason;
};

// Tuning record for history
struct TuningRecord {
    std::string id;
    std::chrono::steady_clock::time_point timestamp;
    TuningParameter parameter;
    double oldValue;
    double newValue;
    std::string reason;
    bool approved;
    bool successful;
    double measuredImprovement;
    std::string rollbackReason;
};

// Performance snapshot for learning
struct PerformanceSnapshot {
    std::chrono::steady_clock::time_point timestamp;
    
    // Current parameters
    std::map<TuningParameter, double> parameters;
    
    // Metrics
    double latencyMs;
    double throughput;
    double errorRate;
    double cpuUtilization;
    double memoryUtilization;
    double gpuUtilization;
    double gpuMemoryUtilization;
    
    // Workload characteristics
    uint32_t requestRate;
    uint32_t concurrentUsers;
    std::string workloadType;  // e.g., "batch", "streaming", "mixed"
};

// Auto-tuning engine
class AutoTuningEngine {
public:
    AutoTuningEngine(PerformanceProfiler* profiler,
                     BottleneckAnalyzer* analyzer,
                     AlertManager* alertManager);
    ~AutoTuningEngine();
    
    // Lifecycle
    bool initialize(const AutoTuningConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    bool isEnabled() const { return config_.enabled; }
    
    // Control
    void enable();
    void disable();
    void setDryRun(bool dryRun);
    bool isDryRun() const { return config_.constraints.dryRun; }
    
    // Manual tuning
    void triggerTuning();
    bool applyAdjustment(const TuningAdjustment& adjustment);
    bool rollbackAdjustment(const std::string& adjustmentId);
    
    // Approval workflow
    std::vector<TuningAdjustment> getPendingAdjustments() const;
    bool approveAdjustment(const std::string& adjustmentId);
    bool rejectAdjustment(const std::string& adjustmentId, const std::string& reason);
    
    // History and learning
    std::vector<TuningRecord> getTuningHistory(uint32_t days = 30) const;
    std::vector<PerformanceSnapshot> getPerformanceHistory(uint32_t hours = 24) const;
    
    // Learning model
    bool saveLearningModel(const std::string& path);
    bool loadLearningModel(const std::string& path);
    void resetLearning();
    
    // Recommendations
    struct Recommendation {
        TuningParameter parameter;
        double currentValue;
        double recommendedValue;
        double expectedImprovement;
        double confidence;
        std::string reasoning;
        std::vector<std::string> risks;
    };
    std::vector<Recommendation> getRecommendations() const;
    
    // Statistics
    struct TuningStats {
        uint64_t totalAdjustments;
        uint64_t successfulAdjustments;
        uint64_t rolledBackAdjustments;
        uint64_t rejectedAdjustments;
        
        double avgImprovement;
        double bestImprovement;
        double worstRegression;
        
        std::map<TuningParameter, uint64_t> adjustmentsByParameter;
        std::map<std::string, uint64_t> adjustmentsByStrategy;
        
        double currentLatency;
        double currentThroughput;
        double currentErrorRate;
    };
    TuningStats getStats() const;
    
    // Configuration
    AutoTuningConfig getConfig() const { return config_; }
    bool updateConfig(const AutoTuningConfig& config);
    
    // Callbacks
    using TuningCallback = std::function<void(const TuningAdjustment&)>;
    void setTuningCallback(TuningCallback callback);
    
    using RecommendationCallback = std::function<void(const std::vector<Recommendation>&)>;
    void setRecommendationCallback(RecommendationCallback callback);

private:
    // Internal loops
    void tuningLoop();
    void evaluationLoop();
    void learningLoop();
    
    // Tuning strategies
    std::vector<TuningAdjustment> generateAdjustmentsGradientDescent();
    std::vector<TuningAdjustment> generateAdjustmentsBayesian();
    std::vector<TuningAdjustment> generateAdjustmentsGenetic();
    std::vector<TuningAdjustment> generateAdjustmentsRL();
    std::vector<TuningAdjustment> generateAdjustmentsRuleBased();
    
    // Analysis
    PerformanceSnapshot captureSnapshot();
    double calculateObjective(const PerformanceSnapshot& snapshot);
    double calculateImprovement(const PerformanceSnapshot& before,
                                const PerformanceSnapshot& after);
    bool shouldRollback(const TuningAdjustment& adjustment);
    
    // Parameter management
    double getCurrentValue(TuningParameter param);
    bool setParameterValue(TuningParameter param, double value);
    bool validateAdjustment(const TuningAdjustment& adjustment);
    
    // Learning
    void updateLearningModel(const TuningAdjustment& adjustment,
                             const PerformanceSnapshot& before,
                             const PerformanceSnapshot& after);
    std::vector<Recommendation> generateRecommendationsFromModel();
    
    // Threading
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::thread tuningThread_;
    std::thread evalThread_;
    std::thread learningThread_;
    mutable std::mutex mutex_;
    
    // Dependencies
    PerformanceProfiler* profiler_;
    BottleneckAnalyzer* analyzer_;
    AlertManager* alertManager_;
    
    // Configuration
    AutoTuningConfig config_;
    
    // State
    std::map<std::string, TuningAdjustment> pendingAdjustments_;
    std::map<std::string, TuningAdjustment> activeAdjustments_;
    std::vector<TuningRecord> tuningHistory_;
    std::vector<PerformanceSnapshot> performanceHistory_;
    
    // Current parameters
    std::map<TuningParameter, double> currentParameters_;
    
    // Statistics
    std::atomic<uint64_t> totalAdjustments_{0};
    std::atomic<uint64_t> successfulAdjustments_{0};
    std::atomic<uint64_t> rolledBackAdjustments_{0};
    
    // Callbacks
    TuningCallback tuningCallback_;
    RecommendationCallback recommendationCallback_;
    
    // ID generation
    std::atomic<uint64_t> adjustmentIdCounter_{0};
};

// Workload classifier
class WorkloadClassifier {
public:
    // Classification
    enum class WorkloadType {
        BATCH,          // Batch inference
        STREAMING,      // Streaming/real-time
        INTERACTIVE,    // Interactive/chat
        MIXED,          // Mixed workload
        UNKNOWN
    };
    
    WorkloadType classify(const PerformanceSnapshot& snapshot);
    
    // Pattern detection
    struct WorkloadPattern {
        WorkloadType type;
        float confidence;
        uint32_t burstiness;      // 0-100
        uint32_t predictability;  // 0-100
        std::vector<std::string> characteristics;
    };
    WorkloadPattern analyzePattern(uint32_t hours = 1);
    
    // Forecasting
    struct Forecast {
        std::chrono::system_clock::time_point timestamp;
        WorkloadType predictedType;
        float expectedLoad;
        float confidence;
    };
    std::vector<Forecast> forecast(uint32_t hoursAhead = 1);
    
private:
    std::vector<PerformanceSnapshot> history_;
    mutable std::mutex mutex_;
};

} // namespace Performance
} // namespace RawrXD
