/**
 * PerformanceProfiler.hpp
 *
 * Phase H Batch 1/5: Performance Profiling & Analysis
 *
 * Comprehensive performance profiling with CPU, memory, and I/O analysis.
 * Identifies bottlenecks and optimization opportunities.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <memory>
#include <functional>
#include <atomic>

namespace Performance {

// ============================================================================
// Profile Types
// ============================================================================

enum class ProfileType {
    CPU,            // CPU usage profiling
    MEMORY,         // Memory allocation profiling
    IO,             // Disk/network I/O profiling
    GPU,            // GPU utilization profiling
    CACHE,          // Cache hit/miss profiling
    LOCK,           // Lock contention profiling
    SYSCALL,        // System call profiling
    CUSTOM          // User-defined profiling
};

std::string ProfileTypeToString(ProfileType type);

// ============================================================================
// Profile Sample
// ============================================================================

/**
 * Single performance sample.
 */
struct ProfileSample {
    uint64_t timestamp;
    ProfileType type;
    std::string name;
    double value;
    std::string unit;
    std::map<std::string, std::string> metadata;
    
    ProfileSample();
    ProfileSample(ProfileType type, const std::string& name, double value, const std::string& unit);
    
    std::string ToJson() const;
};

// ============================================================================
// Profile Region
// ============================================================================

/**
 * Profiled code region.
 */
class ProfileRegion {
public:
    ProfileRegion(const std::string& name, ProfileType type = ProfileType::CPU);
    ~ProfileRegion();
    
    void Enter();
    void Exit();
    
    uint64_t GetTotalTimeNs() const { return totalTimeNs_; }
    uint64_t GetCallCount() const { return callCount_; }
    double GetAverageTimeMs() const;
    
    std::string GetName() const { return name_; }
    ProfileType GetType() const { return type_; }
    
private:
    std::string name_;
    ProfileType type_;
    
    std::atomic<uint64_t> totalTimeNs_{0};
    std::atomic<uint64_t> callCount_{0};
    
    thread_local static uint64_t enterTime_;
};

// ============================================================================
// CPU Profiler
// ============================================================================

/**
 * CPU performance profiler.
 */
class CpuProfiler {
public:
    struct Config {
        uint64_t sampleIntervalMs = 10;
        bool captureCallStacks = true;
        uint32_t maxCallStackDepth = 50;
    };
    
    explicit CpuProfiler(const Config& config = Config{});
    ~CpuProfiler();
    
    bool Initialize();
    void Shutdown();
    
    void Start();
    void Stop();
    void Pause();
    void Resume();
    
    // Get results
    std::vector<ProfileSample> GetSamples() const;
    std::map<std::string, double> GetHotspots() const;
    std::map<std::string, double> GetCallTree() const;
    
    // Export
    std::string ExportFlameGraph() const;
    std::string ExportJson() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    
    std::vector<ProfileSample> samples_;
    mutable std::mutex samplesMutex_;
    
    std::thread samplerThread_;
    
    void SamplerLoop();
    void CaptureSample();
    std::vector<std::string> GetCallStack();
};

// ============================================================================
// Memory Profiler
// ============================================================================

/**
 * Memory allocation profiler.
 */
class MemoryProfiler {
public:
    struct Allocation {
        void* address;
        size_t size;
        std::string type;
        std::string file;
        uint32_t line;
        uint64_t timestamp;
        std::vector<std::string> callStack;
    };
    
    struct Config {
        bool trackAllocations = true;
        bool trackCallStacks = true;
        bool detectLeaks = true;
        size_t sampleRate = 1;  // Sample every N allocations
    };
    
    explicit MemoryProfiler(const Config& config = Config{});
    ~MemoryProfiler();
    
    bool Initialize();
    void Shutdown();
    
    // Allocation tracking
    void TrackAllocation(void* ptr, size_t size, const std::string& type,
                         const std::string& file, uint32_t line);
    void TrackDeallocation(void* ptr);
    
    // Analysis
    std::vector<Allocation> GetActiveAllocations() const;
    std::map<std::string, size_t> GetAllocationsByType() const;
    std::map<std::string, size_t> GetAllocationsByFile() const;
    std::vector<Allocation> GetLeaks() const;
    
    // Statistics
    size_t GetTotalAllocated() const;
    size_t GetTotalFreed() const;
    size_t GetCurrentUsage() const;
    size_t GetPeakUsage() const;
    
    // Export
    std::string ExportHeapDump() const;
    std::string ExportJson() const;
    
private:
    Config config_;
    
    std::map<void*, Allocation> allocations_;
    mutable std::mutex allocationsMutex_;
    
    std::atomic<size_t> totalAllocated_{0};
    std::atomic<size_t> totalFreed_{0};
    std::atomic<size_t> currentUsage_{0};
    std::atomic<size_t> peakUsage_{0};
    
    std::atomic<uint64_t> allocationCounter_{0};
};

// ============================================================================
// I/O Profiler
// ============================================================================

/**
 * I/O operation profiler.
 */
class IoProfiler {
public:
    struct IoOperation {
        std::string path;
        std::string operation;  // read, write, open, close
        uint64_t startTime;
        uint64_t endTime;
        size_t bytesTransferred;
        bool async;
    };
    
    struct Config {
        bool trackDiskIo = true;
        bool trackNetworkIo = true;
        uint64_t slowIoThresholdMs = 100;
    };
    
    explicit IoProfiler(const Config& config = Config{});
    
    void RecordOperation(const IoOperation& op);
    
    // Analysis
    std::vector<IoOperation> GetSlowOperations() const;
    std::map<std::string, uint64_t> GetIoByPath() const;
    std::map<std::string, double> GetAverageLatencyByOperation() const;
    
    // Statistics
    uint64_t GetTotalOperations() const;
    uint64_t GetTotalBytesRead() const;
    uint64_t GetTotalBytesWritten() const;
    double GetAverageLatencyMs() const;
    
private:
    Config config_;
    std::vector<IoOperation> operations_;
    mutable std::mutex operationsMutex_;
    
    std::atomic<uint64_t> totalOperations_{0};
    std::atomic<uint64_t> totalBytesRead_{0};
    std::atomic<uint64_t> totalBytesWritten_{0};
};

// ============================================================================
// GPU Profiler
// ============================================================================

/**
 * GPU performance profiler.
 */
class GpuProfiler {
public:
    struct GpuSample {
        uint64_t timestamp;
        float utilization;      // 0-100%
        float memoryUtilization; // 0-100%
        size_t memoryUsed;
        size_t memoryTotal;
        float temperature;
        uint32_t fanSpeed;
    };
    
    struct KernelExecution {
        std::string name;
        uint64_t startTime;
        uint64_t endTime;
        size_t gridSize;
        size_t blockSize;
        size_t sharedMemory;
    };
    
    GpuProfiler();
    ~GpuProfiler();
    
    bool Initialize();
    void Shutdown();
    
    void StartSampling();
    void StopSampling();
    
    void RecordKernelExecution(const KernelExecution& kernel);
    
    // Results
    std::vector<GpuSample> GetSamples() const;
    std::vector<KernelExecution> GetKernelExecutions() const;
    
    // Statistics
    float GetAverageUtilization() const;
    float GetPeakUtilization() const;
    size_t GetPeakMemoryUsage() const;
    
private:
    std::atomic<bool> running_{false};
    std::thread samplerThread_;
    
    std::vector<GpuSample> samples_;
    mutable std::mutex samplesMutex_;
    
    std::vector<KernelExecution> kernels_;
    mutable std::mutex kernelsMutex_;
    
    void SamplerLoop();
    GpuSample CaptureSample();
};

// ============================================================================
// Cache Profiler
// ============================================================================

/**
 * Cache performance profiler.
 */
class CacheProfiler {
public:
    struct CacheStats {
        uint64_t hits = 0;
        uint64_t misses = 0;
        uint64_t evictions = 0;
        uint64_t size = 0;
        uint64_t capacity = 0;
    };
    
    void RecordHit(const std::string& cacheName);
    void RecordMiss(const std::string& cacheName);
    void RecordEviction(const std::string& cacheName);
    void UpdateSize(const std::string& cacheName, uint64_t size, uint64_t capacity);
    
    CacheStats GetStats(const std::string& cacheName) const;
    std::map<std::string, CacheStats> GetAllStats() const;
    
    double GetHitRate(const std::string& cacheName) const;
    
private:
    std::map<std::string, CacheStats> stats_;
    mutable std::mutex statsMutex_;
};

// ============================================================================
// Lock Profiler
// ============================================================================

/**
 * Lock contention profiler.
 */
class LockProfiler {
public:
    struct LockStats {
        std::string name;
        uint64_t acquireCount = 0;
        uint64_t contentionCount = 0;
        uint64_t totalWaitTimeNs = 0;
        uint64_t maxWaitTimeNs = 0;
        uint64_t currentHolders = 0;
    };
    
    void RecordAcquire(const std::string& lockName, uint64_t waitTimeNs);
    void RecordRelease(const std::string& lockName);
    
    LockStats GetStats(const std::string& lockName) const;
    std::vector<LockStats> GetHotLocks() const;
    
private:
    std::map<std::string, LockStats> stats_;
    mutable std::mutex statsMutex_;
};

// ============================================================================
// Performance Profiler
// ============================================================================

/**
 * Main performance profiler coordinating all profilers.
 */
class PerformanceProfiler {
public:
    struct Config {
        bool enableCpuProfiling = true;
        bool enableMemoryProfiling = true;
        bool enableIoProfiling = true;
        bool enableGpuProfiling = true;
        bool enableCacheProfiling = true;
        bool enableLockProfiling = true;
    };
    
    explicit PerformanceProfiler(const Config& config = Config{});
    ~PerformanceProfiler();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Control
    void StartProfiling();
    void StopProfiling();
    void PauseProfiling();
    void ResumeProfiling();
    bool IsProfiling() const;
    
    // Access individual profilers
    CpuProfiler* GetCpuProfiler();
    MemoryProfiler* GetMemoryProfiler();
    IoProfiler* GetIoProfiler();
    GpuProfiler* GetGpuProfiler();
    CacheProfiler* GetCacheProfiler();
    LockProfiler* GetLockProfiler();
    
    // High-level API
    void BeginRegion(const std::string& name, ProfileType type = ProfileType::CPU);
    void EndRegion(const std::string& name);
    
    // Scoped profiling
    class ScopedRegion {
    public:
        ScopedRegion(PerformanceProfiler* profiler, const std::string& name, ProfileType type = ProfileType::CPU);
        ~ScopedRegion();
        
    private:
        PerformanceProfiler* profiler_;
        std::string name_;
    };
    
    // Analysis
    std::string GenerateReport() const;
    std::vector<std::string> GetBottlenecks() const;
    std::map<std::string, std::string> GetRecommendations() const;
    
    // Export
    void ExportToChromeTracing(const std::string& filepath) const;
    void ExportToFlameGraph(const std::string& filepath) const;
    std::string ExportJson() const;
    
    // Status
    std::string GetStatusJson() const;
    
private:
    Config config_;
    
    std::unique_ptr<CpuProfiler> cpuProfiler_;
    std::unique_ptr<MemoryProfiler> memoryProfiler_;
    std::unique_ptr<IoProfiler> ioProfiler_;
    std::unique_ptr<GpuProfiler> gpuProfiler_;
    std::unique_ptr<CacheProfiler> cacheProfiler_;
    std::unique_ptr<LockProfiler> lockProfiler_;
    
    std::map<std::string, std::unique_ptr<ProfileRegion>> regions_;
    mutable std::mutex regionsMutex_;
    
    std::atomic<bool> profiling_{false};
};

// ============================================================================
// Macros
// ============================================================================

#define PROFILE_SCOPE(profiler, name) \
    Performance::PerformanceProfiler::ScopedRegion __profile_region__(profiler, name)

#define PROFILE_SCOPE_TYPE(profiler, name, type) \
    Performance::PerformanceProfiler::ScopedRegion __profile_region__(profiler, name, type)

} // namespace Performance
