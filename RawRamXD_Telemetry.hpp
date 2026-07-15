// =============================================================================
// RawRamXD_Telemetry.hpp - Comprehensive Metrics Collection
// =============================================================================

#ifndef RAWRAMXD_TELEMETRY_HPP
#define RAWRAMXD_TELEMETRY_HPP

#include "RawRamXD.hpp"
#include "RawRamXD_Policy.hpp"
#include <chrono>
#include <deque>
#include <map>

namespace rawramxd {

// =============================================================================
// Time-Series Metrics Storage
// =============================================================================

template<typename T, size_t N>
class CircularBuffer {
public:
    void push(T value) {
        if (buffer_.size() < N) {
            buffer_.push_back(value);
        } else {
            buffer_[writeIndex_] = value;
            writeIndex_ = (writeIndex_ + 1) % N;
        }
        count_++;
    }
    
    T average() const {
        if (buffer_.empty()) return T{};
        T sum = std::accumulate(buffer_.begin(), buffer_.end(), T{});
        return sum / buffer_.size();
    }
    
    T percentile(double p) const {
        if (buffer_.empty()) return T{};
        auto sorted = buffer_;
        std::sort(sorted.begin(), sorted.end());
        size_t idx = static_cast<size_t>(p * sorted.size());
        return sorted[std::min(idx, sorted.size() - 1)];
    }
    
    size_t size() const { return buffer_.size(); }
    void clear() { buffer_.clear(); writeIndex_ = 0; count_ = 0; }
    
private:
    std::vector<T> buffer_;
    size_t writeIndex_ = 0;
    size_t count_ = 0;
};

// =============================================================================
// Detailed Telemetry Collector
// =============================================================================

struct MigrationEvent {
    uint64_t timestamp;
    Handle handle;
    Tier from;
    Tier to;
    double latencyMs;
    bool success;
    size_t bytes;
};

struct AccessEvent {
    uint64_t timestamp;
    Handle handle;
    Tier tier;
    size_t bytes;
    bool hit;  // Was data already resident?
};

struct StallEvent {
    uint64_t timestamp;
    Handle handle;
    Tier needed;
    double durationMs;
    const char* reason;
};

class TelemetryCollector {
public:
    TelemetryCollector();
    
    // Event recording
    void RecordMigration(const MigrationEvent& event);
    void RecordAccess(const AccessEvent& event);
    void RecordStall(const StallEvent& event);
    void RecordPrefetch(Handle handle, bool hit);
    void RecordEviction(Handle handle, Tier from);
    
    // Metric computation
    ResidencyMetrics ComputeMetrics(std::chrono::seconds window = std::chrono::seconds(60));
    
    // Detailed reports
    struct Report {
        ResidencyMetrics metrics;
        std::vector<MigrationEvent> recentMigrations;
        std::vector<StallEvent> recentStalls;
        std::map<Tier, size_t> tierDistribution;
        std::map<AccessPattern, size_t> patternDistribution;
        double totalMigrationBytes;
        double totalStallTimeMs;
    };
    Report GenerateReport();
    
    // Export
    void ExportToCSV(const std::string& filename);
    void ExportToJSON(const std::string& filename);
    
    // Real-time streaming
    using MetricsCallback = std::function<void(const ResidencyMetrics&)>;
    void SetMetricsCallback(MetricsCallback callback, std::chrono::seconds interval);
    
private:
    // Event storage (circular buffers)
    CircularBuffer<MigrationEvent, 10000> migrations_;
    CircularBuffer<AccessEvent, 100000> accesses_;
    CircularBuffer<StallEvent, 1000> stalls_;
    
    // Counters
    std::atomic<uint64_t> prefetchAttempts_{0};
    std::atomic<uint64_t> prefetchHits_{0};
    std::atomic<uint64_t> evictions_{0};
    
    // Callback
    MetricsCallback metricsCallback_;
    std::chrono::seconds callbackInterval_;
    std::thread callbackThread_;
    std::atomic<bool> callbackRunning_{false};
    
    void CallbackLoop();
};

// =============================================================================
// Performance Counters (Hardware-level when available)
// =============================================================================

class PerformanceCounters {
public:
    struct Counters {
        uint64_t dmaBytesRead;
        uint64_t dmaBytesWritten;
        uint64_t pcieReadBytes;
        uint64_t pcieWriteBytes;
        uint64_t gpuUtilization;  // microseconds active
        uint64_t gpuTime;         // total microseconds
        uint64_t pageFaults;
        uint64_t tlbMisses;
    };
    
    static bool Initialize();
    static Counters Sample();
    static Counters Delta(const Counters& previous, const Counters& current);
    
private:
    #ifdef _WIN32
    static HANDLE gpuQueryHandle_;
    #endif
};

// =============================================================================
// Benchmark Harness
// =============================================================================

class ResidencyBenchmark {
public:
    struct Config {
        size_t modelSize;           // Total model size
        size_t kvCacheSize;         // KV cache per layer
        size_t activationSize;      // Activation buffer size
        int numLayers;              // Transformer layers
        int sequenceLength;         // Context length
        int tokensToGenerate;       // Benchmark duration
        std::string policy;         // Which policy to test
    };
    
    struct Results {
        double avgTPS;
        double p99LatencyMs;
        double firstTokenLatencyMs;
        double modelLoadTimeMs;
        ResidencyMetrics residencyMetrics;
        std::map<std::string, double> customMetrics;
    };
    
    static Results Run(const Config& config);
    static void ComparePolicies(const Config& config, 
                               const std::vector<std::string>& policies);
};

// =============================================================================
// Integration with RawrXD
// =============================================================================

class RawrXDIntegration {
public:
    // Initialize RawRamXD with RawrXD configuration
    static bool Initialize(size_t vramSize, size_t ramSize, size_t nvmeSize,
                          const std::string& policy = "LLMInference");
    
    // Model loading integration
    static Handle LoadModelWeights(const std::string& path, 
                                   const std::string& name);
    static Handle AllocateKVCache(size_t size, int layer);
    static Handle AllocateActivations(size_t size, const std::string& name);
    
    // Inference integration
    static void* GetLayerWeights(int layer);
    static void* GetKVCache(int layer);
    static void* GetActivations(const std::string& name);
    
    // Pre-flight residency
    static bool PrepareLayer(int layer);
    static bool PrepareKVCache(int layer);
    
    // Telemetry export
    static void ExportTelemetry(const std::string& path);
    static void PrintStats();
    
    // 24-hour soak test
    static bool RunSoakTest(int hours, const std::string& modelPath);
};

} // namespace rawramxd

#endif // RAWRAMXD_TELEMETRY_HPP