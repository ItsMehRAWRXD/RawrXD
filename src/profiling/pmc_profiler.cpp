//=============================================================================
// PMC Profiler Implementation
// Platform-specific implementations for Windows and Linux
//=============================================================================

#include "pmc_profiler.hpp"
#include <cstdio>
#include <algorithm>

namespace RawrXD {
namespace Profiling {

//=============================================================================
// PMCCounter Implementation
//=============================================================================

PMCCounter::PMCCounter()
    : event_(PMCEvent::CPU_CYCLES)
    , is_running_(false)
    , is_configured_(false)
#if defined(PMC_PLATFORM_LINUX)
    , fd_(-1)
#elif defined(PMC_PLATFORM_WINDOWS)
    , start_value_(0)
#endif
{
}

PMCCounter::~PMCCounter() {
#if defined(PMC_PLATFORM_LINUX)
    if (fd_ >= 0) {
        close(fd_);
    }
#endif
}

PMCCounter::PMCCounter(PMCCounter&& other) noexcept
    : event_(other.event_)
    , is_running_(other.is_running_)
    , is_configured_(other.is_configured_)
#if defined(PMC_PLATFORM_LINUX)
    , fd_(other.fd_)
#elif defined(PMC_PLATFORM_WINDOWS)
    , start_value_(other.start_value_)
#endif
{
#if defined(PMC_PLATFORM_LINUX)
    other.fd_ = -1;
#endif
    other.is_running_ = false;
    other.is_configured_ = false;
}

PMCCounter& PMCCounter::operator=(PMCCounter&& other) noexcept {
    if (this != &other) {
#if defined(PMC_PLATFORM_LINUX)
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = other.fd_;
        other.fd_ = -1;
#elif defined(PMC_PLATFORM_WINDOWS)
        start_value_ = other.start_value_;
#endif
        event_ = other.event_;
        is_running_ = other.is_running_;
        is_configured_ = other.is_configured_;
        
        other.is_running_ = false;
        other.is_configured_ = false;
    }
    return *this;
}

bool PMCCounter::Configure(PMCEvent event) {
    if (is_running_) {
        return false;
    }
    
    event_ = event;
    
#if defined(PMC_PLATFORM_LINUX)
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_HARDWARE;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    
    switch (event) {
        case PMCEvent::CPU_CYCLES:
            attr.config = PERF_COUNT_HW_CPU_CYCLES;
            break;
        case PMCEvent::INSTRUCTIONS_RETIRED:
            attr.config = PERF_COUNT_HW_INSTRUCTIONS;
            break;
        case PMCEvent::CACHE_REFERENCES:
            attr.config = PERF_COUNT_HW_CACHE_REFERENCES;
            break;
        case PMCEvent::L1_CACHE_MISSES:
            attr.config = PERF_COUNT_HW_CACHE_MISSES;
            break;
        case PMCEvent::BRANCH_INSTRUCTIONS:
            attr.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
            break;
        case PMCEvent::BRANCH_MISSES:
            attr.config = PERF_COUNT_HW_BRANCH_MISSES;
            break;
        default:
            // Fall back to raw event
            return ConfigureRaw(static_cast<uint64_t>(event));
    }
    
    fd_ = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd_ < 0) {
        return false;
    }
    
#elif defined(PMC_PLATFORM_WINDOWS)
    // Windows requires ETW or driver support
    // For now, mark as configured but use RDTSC fallback
#endif
    
    is_configured_ = true;
    return true;
}

bool PMCCounter::ConfigureRaw(uint64_t raw_event_code) {
    if (is_running_) {
        return false;
    }
    
#if defined(PMC_PLATFORM_LINUX)
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_RAW;
    attr.config = raw_event_code;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    
    fd_ = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd_ < 0) {
        return false;
    }
#endif
    
    is_configured_ = true;
    return true;
}

bool PMCCounter::Start() {
    if (!is_configured_ || is_running_) {
        return false;
    }
    
#if defined(PMC_PLATFORM_LINUX)
    if (fd_ < 0) {
        return false;
    }
    
    ioctl(fd_, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd_, PERF_EVENT_IOC_ENABLE, 0);
    
#elif defined(PMC_PLATFORM_WINDOWS)
    start_value_ = __rdtsc();
#endif
    
    is_running_ = true;
    return true;
}

bool PMCCounter::Stop() {
    if (!is_running_) {
        return false;
    }
    
#if defined(PMC_PLATFORM_LINUX)
    if (fd_ >= 0) {
        ioctl(fd_, PERF_EVENT_IOC_DISABLE, 0);
    }
#endif
    
    is_running_ = false;
    return true;
}

bool PMCCounter::Reset() {
    if (is_running_) {
        return false;
    }
    
#if defined(PMC_PLATFORM_LINUX)
    if (fd_ >= 0) {
        ioctl(fd_, PERF_EVENT_IOC_RESET, 0);
    }
#elif defined(PMC_PLATFORM_WINDOWS)
    start_value_ = 0;
#endif
    
    return true;
}

uint64_t PMCCounter::Read() const {
    if (!is_configured_) {
        return 0;
    }
    
#if defined(PMC_PLATFORM_LINUX)
    if (fd_ < 0) {
        return 0;
    }
    
    uint64_t value = 0;
    read(fd_, &value, sizeof(value));
    return value;
    
#elif defined(PMC_PLATFORM_WINDOWS)
    if (is_running_) {
        return __rdtsc() - start_value_;
    }
    return 0;
#else
    return 0;
#endif
}

const char* PMCCounter::GetEventName() const {
    return RawrXD::Profiling::GetEventName(event_);
}

//=============================================================================
// PMCSession Implementation
//=============================================================================

PMCSession::PMCSession()
    : is_running_(false)
{
}

PMCSession::~PMCSession() {
    if (is_running_) {
        Stop();
    }
}

bool PMCSession::AddCounter(PMCEvent event) {
    if (is_running_) {
        return false;
    }
    
    if (counters_.size() >= MAX_COUNTERS) {
        return false;
    }
    
    PMCCounter counter;
    if (!counter.Configure(event)) {
        return false;
    }
    
    counters_.push_back(std::move(counter));
    return true;
}

bool PMCSession::AddCounters(const std::vector<PMCEvent>& events) {
    bool all_success = true;
    for (auto event : events) {
        if (!AddCounter(event)) {
            all_success = false;
        }
    }
    return all_success;
}

void PMCSession::ClearCounters() {
    if (is_running_) {
        Stop();
    }
    counters_.clear();
    start_values_.clear();
}

bool PMCSession::Start() {
    if (is_running_ || counters_.empty()) {
        return false;
    }
    
    start_values_.clear();
    start_values_.reserve(counters_.size());
    
    for (auto& counter : counters_) {
        if (!counter.Start()) {
            return false;
        }
        start_values_.push_back(counter.Read());
    }
    
    is_running_ = true;
    return true;
}

bool PMCSession::Stop() {
    if (!is_running_) {
        return false;
    }
    
    for (auto& counter : counters_) {
        counter.Stop();
    }
    
    is_running_ = false;
    return true;
}

bool PMCSession::Reset() {
    if (is_running_) {
        return false;
    }
    
    for (auto& counter : counters_) {
        counter.Reset();
    }
    
    start_values_.clear();
    return true;
}

std::vector<PMCSession::Result> PMCSession::GetResults() const {
    std::vector<Result> results;
    results.reserve(counters_.size());
    
    for (size_t i = 0; i < counters_.size(); ++i) {
        uint64_t current = counters_[i].Read();
        uint64_t start = (i < start_values_.size()) ? start_values_[i] : 0;
        
        Result result;
        result.event = counters_[i].GetEvent();
        result.name = GetEventName(result.event);
        result.value = current;
        result.delta = current - start;
        
        results.push_back(result);
    }
    
    return results;
}

uint64_t PMCSession::GetCounterValue(PMCEvent event) const {
    for (const auto& counter : counters_) {
        if (counter.GetEvent() == event) {
            return counter.Read();
        }
    }
    return 0;
}

//=============================================================================
// ScopedPMCProfile Implementation
//=============================================================================

ScopedPMCProfile::ScopedPMCProfile(const std::vector<PMCEvent>& events) {
    session_.AddCounters(events);
    session_.Start();
}

ScopedPMCProfile::~ScopedPMCProfile() {
    session_.Stop();
}

std::vector<PMCSession::Result> ScopedPMCProfile::GetResults() const {
    return session_.GetResults();
}

//=============================================================================
// Utility Functions
//=============================================================================

bool IsPmcAvailable() {
#if defined(PMC_PLATFORM_LINUX)
    // Try to open a simple counter
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.disabled = 1;
    
    int fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd >= 0) {
        close(fd);
        return true;
    }
    return false;
#elif defined(PMC_PLATFORM_WINDOWS)
    // Windows PMC requires ETW or driver
    // Return true for RDTSC fallback
    return true;
#else
    return false;
#endif
}

std::vector<PMCEventConfig> GetAvailableEvents() {
    std::vector<PMCEventConfig> events;
    
    events.push_back({PMCEvent::CPU_CYCLES, "CPU_CYCLES", "CPU cycles", 0});
    events.push_back({PMCEvent::INSTRUCTIONS_RETIRED, "INSTRUCTIONS_RETIRED", "Instructions retired", 0});
    events.push_back({PMCEvent::CACHE_REFERENCES, "CACHE_REFERENCES", "Cache references", 0});
    events.push_back({PMCEvent::L1_CACHE_MISSES, "L1_CACHE_MISSES", "L1 cache misses", 0});
    events.push_back({PMCEvent::BRANCH_INSTRUCTIONS, "BRANCH_INSTRUCTIONS", "Branch instructions", 0});
    events.push_back({PMCEvent::BRANCH_MISSES, "BRANCH_MISSES", "Branch mispredictions", 0});
    
    return events;
}

const char* GetEventName(PMCEvent event) {
    switch (event) {
        case PMCEvent::CPU_CYCLES: return "CPU Cycles";
        case PMCEvent::INSTRUCTIONS_RETIRED: return "Instructions Retired";
        case PMCEvent::L1_CACHE_MISSES: return "L1 Cache Misses";
        case PMCEvent::L2_CACHE_MISSES: return "L2 Cache Misses";
        case PMCEvent::L3_CACHE_MISSES: return "L3 Cache Misses";
        case PMCEvent::CACHE_REFERENCES: return "Cache References";
        case PMCEvent::BRANCH_INSTRUCTIONS: return "Branch Instructions";
        case PMCEvent::BRANCH_MISSES: return "Branch Mispredictions";
        case PMCEvent::MEMORY_ACCESSES: return "Memory Accesses";
        case PMCEvent::MEMORY_STALLS: return "Memory Stalls";
        case PMCEvent::DTLB_MISSES: return "DTLB Misses";
        case PMCEvent::ITLB_MISSES: return "ITLB Misses";
        case PMCEvent::CONTEXT_SWITCHES: return "Context Switches";
        default: return "Unknown";
    }
}

const char* GetEventDescription(PMCEvent event) {
    switch (event) {
        case PMCEvent::CPU_CYCLES: return "Total CPU cycles elapsed";
        case PMCEvent::INSTRUCTIONS_RETIRED: return "Instructions successfully executed";
        case PMCEvent::L1_CACHE_MISSES: return "L1 cache misses";
        case PMCEvent::L2_CACHE_MISSES: return "L2 cache misses";
        case PMCEvent::L3_CACHE_MISSES: return "L3 cache misses";
        case PMCEvent::CACHE_REFERENCES: return "Total cache references";
        case PMCEvent::BRANCH_INSTRUCTIONS: return "Branch instructions executed";
        case PMCEvent::BRANCH_MISSES: return "Branch mispredictions";
        case PMCEvent::MEMORY_ACCESSES: return "Memory accesses";
        case PMCEvent::MEMORY_STALLS: return "Cycles stalled waiting for memory";
        case PMCEvent::DTLB_MISSES: return "Data TLB misses";
        case PMCEvent::ITLB_MISSES: return "Instruction TLB misses";
        case PMCEvent::CONTEXT_SWITCHES: return "Context switches";
        default: return "";
    }
}

DerivedMetrics CalculateDerivedMetrics(const std::vector<PMCSession::Result>& results) {
    DerivedMetrics metrics = {};
    
    uint64_t cycles = 0;
    uint64_t instructions = 0;
    uint64_t cache_refs = 0;
    uint64_t cache_misses = 0;
    uint64_t branches = 0;
    uint64_t branch_misses = 0;
    
    for (const auto& result : results) {
        switch (result.event) {
            case PMCEvent::CPU_CYCLES:
                cycles = result.delta;
                break;
            case PMCEvent::INSTRUCTIONS_RETIRED:
                instructions = result.delta;
                break;
            case PMCEvent::CACHE_REFERENCES:
                cache_refs = result.delta;
                break;
            case PMCEvent::L1_CACHE_MISSES:
                cache_misses = result.delta;
                break;
            case PMCEvent::BRANCH_INSTRUCTIONS:
                branches = result.delta;
                break;
            case PMCEvent::BRANCH_MISSES:
                branch_misses = result.delta;
                break;
            default:
                break;
        }
    }
    
    if (instructions > 0) {
        metrics.cycles_per_instruction = static_cast<double>(cycles) / instructions;
    }
    
    if (cache_refs > 0) {
        metrics.cache_miss_rate = static_cast<double>(cache_misses) / cache_refs;
    }
    
    if (branches > 0) {
        metrics.branch_mispredict_rate = static_cast<double>(branch_misses) / branches;
    }
    
    if (cycles > 0) {
        // Estimate memory stall ratio (simplified)
        metrics.memory_stall_ratio = static_cast<double>(cache_misses) / cycles;
    }
    
    return metrics;
}

} // namespace Profiling
} // namespace RawrXD
