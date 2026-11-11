// ============================================================================
// LatencyProfiler.hpp - Real-time Latency Profiler
// Instruction-level timing for hot-path detection
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <atomic>

namespace Sovereign {

// Profiler sample
struct ProfilerSample {
    uint64_t address;
    uint64_t cycles;
    uint64_t timestamp;
    uint32_t threadId;
    uint32_t cpuId;
    uint16_t cacheMisses;
    uint16_t branchMispredicts;
};

// Hot function
struct HotFunction {
    std::string name;
    uint64_t address;
    uint64_t totalCycles;
    uint64_t callCount;
    double avgCycles;
    double totalTimeMs;
    uint64_t cacheMisses;
    uint64_t branchMispredicts;
    double hotness; // 0-1 score
};

// Profiler configuration
struct ProfilerConfig {
    uint32_t sampleIntervalUs = 100;
    uint32_t maxSamples = 100000;
    double hotnessThreshold = 0.8;
    bool enableCacheMissTracking = true;
    bool enableBranchTracking = true;
    bool enableCPUMigrationTracking = true;
    std::vector<std::string> includeModules;
    std::vector<std::string> excludeModules;
};

// Latency profiler
class LatencyProfiler {
public:
    LatencyProfiler();
    ~LatencyProfiler();

    bool Initialize(const ProfilerConfig& config);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    void Start();
    void Stop();
    bool IsRunning() const { return running_.load(); }

    void AddSample(const ProfilerSample& sample);
    std::vector<HotFunction> GetHotFunctions() const;
    std::vector<HotFunction> GetHotFunctionsByModule(const std::string& module) const;

    void SetSymbolResolver(std::function<std::string(uint64_t)> resolver);
    void SetHotFunctionCallback(std::function<void(const HotFunction&)> callback);

    void Clear();
    void Export(const std::string& path);

    struct ProfilerStats {
        uint64_t totalSamples;
        uint64_t hotFunctions;
        double avgSampleRate;
        double profilingOverhead;
    };
    ProfilerStats GetStats() const;

private:
    bool initialized_ = false;
    std::atomic<bool> running_{false};
    ProfilerConfig config_;
    
    std::vector<ProfilerSample> samples_;
    std::unordered_map<uint64_t, HotFunction> hotFunctions_;
    
    std::function<std::string(uint64_t)> symbolResolver_;
    std::function<void(const HotFunction&)> hotCallback_;
    
    mutable std::mutex mutex_;
    std::thread profilerThread_;
    
    void ProfilerLoop();
    void ProcessSample(const ProfilerSample& sample);
    void DetectHotFunctions();
    double CalculateHotness(const HotFunction& func) const;
};

// Cache-line alignment engine
class CacheLineAligner {
public:
    CacheLineAligner();
    ~CacheLineAligner();

    void* AlignAllocate(size_t size, size_t alignment = 64);
    void AlignFree(void* ptr);
    
    bool IsAligned(void* ptr, size_t alignment = 64) const;
    void* AlignPointer(void* ptr, size_t alignment = 64) const;
    
    struct AlignmentStats {
        size_t totalAllocated;
        size_t totalWasted;
        size_t allocations;
        size_t alignmentFailures;
    };
    AlignmentStats GetStats() const { return stats_; }
    void ResetStats();

private:
    AlignmentStats stats_;
    mutable std::mutex mutex_;
};

// Heuristic pruner
class HeuristicPruner {
public:
    HeuristicPruner();
    ~HeuristicPruner();

    void AddHeuristic(const std::string& name, std::function<double()> heuristic);
    void RemoveHeuristic(const std::string& name);
    
    double Evaluate(const std::string& name) const;
    std::vector<std::pair<std::string, double>> EvaluateAll() const;
    
    bool ShouldPrune(const std::string& name, double threshold = 0.3) const;
    void PruneBelow(double threshold = 0.3);
    
    void SetWeight(const std::string& name, double weight);
    double GetWeight(const std::string& name) const;

private:
    struct Heuristic {
        std::string name;
        std::function<double()> func;
        double weight;
    };
    std::unordered_map<std::string, Heuristic> heuristics_;
    mutable std::mutex mutex_;
};

// Instruction-stream tracer
class InstructionTracer {
public:
    InstructionTracer();
    ~InstructionTracer();

    bool Initialize();
    void Shutdown();

    void StartTracing(uint64_t address, size_t size);
    void StopTracing();
    bool IsTracing() const { return tracing_.load(); }

    struct TraceEntry {
        uint64_t address;
        uint32_t length;
        uint32_t count;
        uint64_t totalCycles;
        uint8_t bytes[16];
    };
    std::vector<TraceEntry> GetTrace() const;
    void ClearTrace();
    void ExportTrace(const std::string& path);

private:
    std::atomic<bool> tracing_{false};
    std::vector<TraceEntry> trace_;
    mutable std::mutex mutex_;
};

// Hot-path JIT compiler
class HotPathJIT {
public:
    HotPathJIT();
    ~HotPathJIT();

    bool Initialize();
    void Shutdown();

    bool Compile(const HotFunction& func);
    bool IsCompiled(uint64_t address) const;
    void* GetCompiledCode(uint64_t address) const;

    struct JITStats {
        uint64_t compilations;
        uint64_t cacheHits;
        uint64_t cacheMisses;
        size_t codeSize;
        double avgCompileTimeMs;
    };
    JITStats GetStats() const;

private:
    std::unordered_map<uint64_t, void*> compiledCode_;
    JITStats stats_;
    mutable std::mutex mutex_;
    uint8_t* codeCache_ = nullptr;
    size_t codeCacheSize_ = 0;
    size_t codeCacheOffset_ = 0;
};

} // namespace Sovereign
