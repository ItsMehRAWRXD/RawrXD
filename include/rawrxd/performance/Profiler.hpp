#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <memory>
#include <functional>

namespace rawrxd {
namespace performance {

// Profile data for a single operation
struct ProfileData {
    std::string name;
    std::string category;
    std::chrono::high_resolution_clock::time_point startTime;
    std::chrono::high_resolution_clock::time_point endTime;
    float durationMs = 0.0f;
    int callCount = 0;
    float totalTimeMs = 0.0f;
    float minTimeMs = 0.0f;
    float maxTimeMs = 0.0f;
    float avgTimeMs = 0.0f;
    size_t memoryAllocated = 0;
    size_t memoryFreed = 0;
};

// Performance metrics
struct PerformanceMetrics {
    float totalTimeMs = 0.0f;
    float cpuTimeMs = 0.0f;
    size_t peakMemoryMB = 0;
    size_t currentMemoryMB = 0;
    float throughput = 0.0f;  // tokens/sec or ops/sec
    float latencyMs = 0.0f;
    float utilizationPercent = 0.0f;
};

// Profiler scope for RAII profiling
class ProfileScope {
public:
    ProfileScope(const std::string& name, const std::string& category = "general");
    ~ProfileScope();

    void End();

private:
    std::string name_;
    std::string category_;
    std::chrono::high_resolution_clock::time_point start_;
    bool ended_ = false;
};

// Main profiler class
class Profiler {
public:
    Profiler();
    ~Profiler();

    // Start profiling
    void StartProfiling(const std::string& sessionName);
    void StopProfiling();
    bool IsProfiling() const { return profiling_; }

    // Profile regions
    void BeginRegion(const std::string& name, const std::string& category = "general");
    void EndRegion(const std::string& name);

    // Get results
    std::vector<ProfileData> GetResults() const;
    ProfileData GetResult(const std::string& name) const;
    
    // Get aggregated results by category
    std::unordered_map<std::string, ProfileData> GetResultsByCategory() const;

    // Export results
    std::string ExportToJSON() const;
    std::string ExportToChromeTrace() const;  // For chrome://tracing
    std::string ExportToMarkdown() const;

    // Reset
    void Reset();

    // Global instance
    static Profiler& GetInstance();

    // Convenience macros
    #define RAWRXD_PROFILE_SCOPE(name) \
        rawrxd::performance::ProfileScope _profile_scope(name)

    #define RAWRXD_PROFILE_SCOPE_CAT(name, category) \
        rawrxd::performance::ProfileScope _profile_scope(name, category)

    #define RAWRXD_PROFILE_BEGIN(name) \
        rawrxd::performance::Profiler::GetInstance().BeginRegion(name)

    #define RAWRXD_PROFILE_END(name) \
        rawrxd::performance::Profiler::GetInstance().EndRegion(name)

private:
    bool profiling_ = false;
    std::string sessionName_;
    std::unordered_map<std::string, ProfileData> data_;
    std::vector<std::string> activeRegions_;
    std::chrono::high_resolution_clock::time_point sessionStart_;

    void UpdateStats(ProfileData& data, float durationMs);
};

// Memory profiler
class MemoryProfiler {
public:
    static size_t GetCurrentUsage();
    static size_t GetPeakUsage();
    static void ResetPeak();
    
    struct AllocationInfo {
        size_t size;
        std::string file;
        int line;
        std::string function;
    };
    
    static std::unordered_map<void*, AllocationInfo> GetActiveAllocations();
    static std::string GetLeakReport();
};

// GPU profiler (if available)
class GPUProfiler {
public:
    static bool IsAvailable();
    static float GetUtilization();
    static size_t GetMemoryUsed();
    static size_t GetMemoryTotal();
    static float GetTemperature();
};

} // namespace performance
} // namespace rawrxd
