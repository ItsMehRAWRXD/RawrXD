// ============================================================================
// FlameGraphProfiler.hpp - Flame Graph & Memory Profiler
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

// Flame graph node
struct FlameNode {
    std::string name;
    uint64_t selfTime;
    uint64_t totalTime;
    uint64_t callCount;
    std::vector<FlameNode> children;
};

// Flame graph
struct FlameGraph {
    std::vector<FlameNode> roots;
    uint64_t totalTime;
    uint64_t totalCalls;
    double maxDepth;
};

// Profiler sample
struct ProfilerSample {
    uint64_t timestamp;
    uint64_t threadId;
    std::vector<uint64_t> stackTrace;
    uint64_t cpuCycles;
    uint64_t memoryBytes;
};

// Flame graph profiler
class FlameGraphProfiler {
public:
    FlameGraphProfiler();
    ~FlameGraphProfiler();

    bool Initialize(size_t maxSamples = 100000);
    void Shutdown();

    void Start();
    void Stop();
    bool IsRunning() const { return running_.load(); }

    void AddSample(const ProfilerSample& sample);
    FlameGraph BuildFlameGraph() const;
    FlameGraph BuildFlameGraphForThread(uint64_t threadId) const;

    bool ExportToSVG(const std::string& path);
    bool ExportToJSON(const std::string& path);
    bool ExportToFold(const std::string& path);

    void SetSymbolResolver(std::function<std::string(uint64_t)> resolver);

    struct ProfilerStats {
        uint64_t totalSamples;
        uint64_t totalThreads;
        uint64_t uniqueFunctions;
        double samplingRateHz;
    };
    ProfilerStats GetStats() const { return stats_; }

private:
    std::atomic<bool> running_{false};
    std::vector<ProfilerSample> samples_;
    ProfilerStats stats_;
    size_t maxSamples_;
    std::function<std::string(uint64_t)> symbolResolver_;
    mutable std::mutex mutex_;
    std::thread profilerThread_;
    
    void ProfilerLoop();
    void MergeSampleIntoGraph(FlameNode& root, const ProfilerSample& sample) const;
    std::string RenderSVGNode(const FlameNode& node, double x, double y, double width, double scale, int depth) const;
};

// Memory profiler
class MemoryProfiler {
public:
    MemoryProfiler();
    ~MemoryProfiler();

    bool Initialize();
    void Shutdown();

    void Start();
    void Stop();
    bool IsRunning() const { return running_.load(); }

    void RecordAllocation(void* ptr, size_t size, const std::string& tag = "");
    void RecordDeallocation(void* ptr);
    void RecordReallocation(void* oldPtr, void* newPtr, size_t newSize);

    struct MemorySnapshot {
        uint64_t timestamp;
        uint64_t totalAllocated;
        uint64_t totalFreed;
        uint64_t currentUsage;
        uint64_t peakUsage;
        uint64_t allocationCount;
        uint64_t deallocationCount;
        std::unordered_map<std::string, uint64_t> tagBreakdown;
    };

    MemorySnapshot GetSnapshot() const;
    MemorySnapshot GetDelta() const;
    void ResetPeak();

    bool ExportToJSON(const std::string& path);
    bool ExportToCSV(const std::string& path);

    struct MemStats {
        uint64_t totalAllocations;
        uint64_t totalDeallocations;
        uint64_t currentAllocations;
        uint64_t peakMemory;
        uint64_t currentMemory;
    };
    MemStats GetStats() const { return stats_; }

private:
    std::atomic<bool> running_{false};
    MemStats stats_;
    MemorySnapshot lastSnapshot_;
    
    struct AllocRecord {
        void* ptr;
        size_t size;
        std::string tag;
        uint64_t timestamp;
    };
    std::unordered_map<void*, AllocRecord> allocations_;
    
    mutable std::mutex mutex_;
    std::thread profilerThread_;
    
    void ProfilerLoop();
};

} // namespace Sovereign
