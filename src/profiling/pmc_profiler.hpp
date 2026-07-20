//=============================================================================
// PMC Profiler - Performance Monitoring Counter Support
// Hardware-level profiling for cache misses, branch mispredictions, etc.
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <array>

namespace RawrXD {
namespace Profiling {

//=============================================================================
// Platform Detection
//=============================================================================

#if defined(_WIN32)
    #define PMC_PLATFORM_WINDOWS
    #include <windows.h>
    #include <intrin.h>
#elif defined(__linux__)
    #define PMC_PLATFORM_LINUX
    #include <unistd.h>
    #include <linux/perf_event.h>
    #include <linux/hw_breakpoint.h>
    #include <sys/syscall.h>
    #include <sys/ioctl.h>
    #include <fcntl.h>
    #include <cstring>
#else
    #define PMC_PLATFORM_UNSUPPORTED
#endif

//=============================================================================
// PMC Event Types
//=============================================================================

enum class PMCEvent : uint32_t {
    // CPU Cycles
    CPU_CYCLES = 0,
    
    // Instructions
    INSTRUCTIONS_RETIRED = 1,
    
    // Cache
    L1_CACHE_MISSES = 2,
    L2_CACHE_MISSES = 3,
    L3_CACHE_MISSES = 4,
    CACHE_REFERENCES = 5,
    
    // Branches
    BRANCH_INSTRUCTIONS = 6,
    BRANCH_MISSES = 7,
    
    // Memory
    MEMORY_ACCESSES = 8,
    MEMORY_STALLS = 9,
    
    // TLB
    DTLB_MISSES = 10,
    ITLB_MISSES = 11,
    
    // Context switches
    CONTEXT_SWITCHES = 12,
    
    // Custom
    CUSTOM = 0xFFFFFFFF
};

struct PMCEventConfig {
    PMCEvent event;
    const char* name;
    const char* description;
    uint64_t raw_code;  // Platform-specific raw event code
};

//=============================================================================
// PMC Counter
//=============================================================================

class PMCCounter {
public:
    PMCCounter();
    ~PMCCounter();
    
    // Disable copy
    PMCCounter(const PMCCounter&) = delete;
    PMCCounter& operator=(const PMCCounter&) = delete;
    
    // Enable move
    PMCCounter(PMCCounter&& other) noexcept;
    PMCCounter& operator=(PMCCounter&& other) noexcept;
    
    // Configuration
    bool Configure(PMCEvent event);
    bool ConfigureRaw(uint64_t raw_event_code);
    
    // Control
    bool Start();
    bool Stop();
    bool Reset();
    
    // Read
    uint64_t Read() const;
    bool IsRunning() const { return is_running_; }
    
    // Event info
    PMCEvent GetEvent() const { return event_; }
    const char* GetEventName() const;
    
private:
    PMCEvent event_;
    bool is_running_;
    bool is_configured_;
    
#if defined(PMC_PLATFORM_LINUX)
    int fd_;  // perf_event_open file descriptor
#elif defined(PMC_PLATFORM_WINDOWS)
    // Windows uses ETW or hardware PMC via driver
    // For now, use RDTSC as fallback
    uint64_t start_value_;
#endif
};

//=============================================================================
// PMC Session - Multiple Counters
//=============================================================================

class PMCSession {
public:
    static constexpr size_t MAX_COUNTERS = 8;
    
    PMCSession();
    ~PMCSession();
    
    // Configuration
    bool AddCounter(PMCEvent event);
    bool AddCounters(const std::vector<PMCEvent>& events);
    void ClearCounters();
    
    // Control
    bool Start();
    bool Stop();
    bool Reset();
    
    // Results
    struct Result {
        PMCEvent event;
        std::string name;
        uint64_t value;
        uint64_t delta;  // Since last read
    };
    
    std::vector<Result> GetResults() const;
    uint64_t GetCounterValue(PMCEvent event) const;
    
    // Utility
    bool IsRunning() const { return is_running_; }
    size_t GetCounterCount() const { return counters_.size(); }
    
private:
    std::vector<PMCCounter> counters_;
    std::vector<uint64_t> start_values_;
    bool is_running_;
};

//=============================================================================
// Scoped Profiler - RAII wrapper
//=============================================================================

class ScopedPMCProfile {
public:
    explicit ScopedPMCProfile(const std::vector<PMCEvent>& events);
    ~ScopedPMCProfile();
    
    // Get results before destruction
    std::vector<PMCSession::Result> GetResults() const;
    
private:
    PMCSession session_;
};

//=============================================================================
// Platform-Specific Implementations
//=============================================================================

#ifdef PMC_PLATFORM_LINUX

// Linux perf_event_open syscall wrapper
inline int perf_event_open(struct perf_event_attr* attr,
                           pid_t pid, int cpu, int group_fd,
                           unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// Common event configurations for x86_64
namespace x86_64_events {
    constexpr uint64_t CPU_CYCLES = 0x3C;           // CPU_CLK_UNHALTED.THREAD
    constexpr uint64_t INSTRUCTIONS_RETIRED = 0xC0; // INST_RETIRED.ANY
    constexpr uint64_t L1_CACHE_MISSES = 0x2E;    // LONGEST_LAT_CACHE.MISS
    constexpr uint64_t L2_CACHE_MISSES = 0x24;      // L2_RQSTS.MISS
    constexpr uint64_t L3_CACHE_MISSES = 0xB0;      // OFFCORE_REQUESTS.DEMAND_DATA_RD
    constexpr uint64_t BRANCH_INSTRUCTIONS = 0xC4; // BR_INST_RETIRED.ALL_BRANCHES
    constexpr uint64_t BRANCH_MISSES = 0xC5;        // BR_MISP_RETIRED.ALL_BRANCHES
    constexpr uint64_t DTLB_MISSES = 0x08;          // DTLB_LOAD_MISSES.MISS_CAUSES_A_WALK
}

#endif  // PMC_PLATFORM_LINUX

//=============================================================================
// Utility Functions
//=============================================================================

// Check if PMC is available on this platform
bool IsPmcAvailable();

// Get available events for this platform
std::vector<PMCEventConfig> GetAvailableEvents();

// Convert event to string
const char* GetEventName(PMCEvent event);
const char* GetEventDescription(PMCEvent event);

// Calculate derived metrics
struct DerivedMetrics {
    double cycles_per_instruction;
    double cache_miss_rate;      // L1 misses / cache references
    double branch_mispredict_rate;
    double memory_stall_ratio;
};

DerivedMetrics CalculateDerivedMetrics(const std::vector<PMCSession::Result>& results);

} // namespace Profiling
} // namespace RawrXD
