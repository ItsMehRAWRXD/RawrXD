//=============================================================================
// Flame Graph Generator
// Generates folded stack traces for flame graph visualization
// Output format compatible with FlameGraph.pl and speedscope
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <stack>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <functional>

namespace RawrXD {
namespace Profiling {

//=============================================================================
// Stack Frame
//=============================================================================

struct StackFrame {
    const char* name;
    const char* file;
    uint32_t line;
    
    bool operator==(const StackFrame& other) const {
        return name == other.name && file == other.file && line == other.line;
    }
};

struct StackFrameHash {
    size_t operator()(const StackFrame& f) const {
        return std::hash<const char*>{}(f.name) ^ 
               (std::hash<const char*>{}(f.file) << 1) ^
               (std::hash<uint32_t>{}(f.line) << 2);
    }
};

//=============================================================================
// Sample
//=============================================================================

struct Sample {
    std::vector<StackFrame> stack;
    uint64_t count;
    uint64_t duration_ns;
};

//=============================================================================
// Flame Graph Profiler
//=============================================================================

class FlameGraphProfiler {
public:
    FlameGraphProfiler();
    ~FlameGraphProfiler();
    
    // Configuration
    void SetSampleInterval(uint32_t interval_ms);
    void SetMaxSamples(size_t max_samples);
    
    // Control
    void Start();
    void Stop();
    void Reset();
    bool IsRunning() const { return is_running_; }
    
    // Manual sampling (for instrumented code)
    void EnterFrame(const char* name, const char* file = nullptr, uint32_t line = 0);
    void ExitFrame();
    
    // Automatic sampling (for periodic profiling)
    void TakeSample();
    
    // Output generation
    void GenerateFoldedStacks(const char* filename) const;
    void GenerateSpeedscopeJSON(const char* filename) const;
    void GenerateChromeTrace(const char* filename) const;
    
    // Statistics
    size_t GetSampleCount() const;
    uint64_t GetTotalDurationNs() const;
    
private:
    struct Frame {
        const char* name;
        const char* file;
        uint32_t line;
        std::chrono::high_resolution_clock::time_point enter_time;
    };
    
    bool is_running_;
    uint32_t sample_interval_ms_;
    size_t max_samples_;
    
    std::stack<Frame> call_stack_;
    std::vector<Sample> samples_;
    mutable std::mutex mutex_;
    
    std::chrono::high_resolution_clock::time_point start_time_;
    uint64_t total_duration_ns_;
    
    // Background sampling thread
    void SamplingThread();
    std::thread sampling_thread_;
    std::atomic<bool> stop_sampling_;
};

//=============================================================================
// Scoped Profiler
//=============================================================================

class ScopedFlameProfile {
public:
    explicit ScopedFlameProfile(FlameGraphProfiler& profiler, const char* name, 
                                const char* file = nullptr, uint32_t line = 0);
    ~ScopedFlameProfile();
    
private:
    FlameGraphProfiler& profiler_;
};

//=============================================================================
// Global Profiler Instance
//=============================================================================

FlameGraphProfiler& GetGlobalFlameProfiler();

// Convenience macros
#define FLAME_PROFILE() \
    RawrXD::Profiling::ScopedFlameProfile _flame_profile_##__LINE__( \
        RawrXD::Profiling::GetGlobalFlameProfiler(), __FUNCTION__, __FILE__, __LINE__)

#define FLAME_PROFILE_NAMED(name) \
    RawrXD::Profiling::ScopedFlameProfile _flame_profile_##__LINE__( \
        RawrXD::Profiling::GetGlobalFlameProfiler(), name, __FILE__, __LINE__)

//=============================================================================
// Platform-Specific Stack Walking
//=============================================================================

#ifdef _WIN32
    #include <windows.h>
    #include <dbghelp.h>
    #pragma comment(lib, "dbghelp.lib")
#else
    #include <execinfo.h>
    #include <cxxabi.h>
#endif

// Capture current call stack
std::vector<StackFrame> CaptureStackTrace(size_t skip_frames = 0, size_t max_depth = 64);

// Demangle C++ symbols
std::string DemangleSymbol(const char* mangled);

} // namespace Profiling
} // namespace RawrXD
