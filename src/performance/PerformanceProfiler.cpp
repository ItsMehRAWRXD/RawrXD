/**
 * PerformanceProfiler.cpp
 *
 * Phase H Batch 1/5: Performance Profiling & Analysis
 */

#include "PerformanceProfiler.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <pdh.h>
#include <pdhmsg.h>
#pragma comment(lib, "pdh.lib")
#else
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>
#endif

namespace Performance {

// ============================================================================
// Profile Type Helpers
// ============================================================================

std::string ProfileTypeToString(ProfileType type) {
    switch (type) {
        case ProfileType::CPU: return "CPU";
        case ProfileType::MEMORY: return "MEMORY";
        case ProfileType::IO: return "IO";
        case ProfileType::GPU: return "GPU";
        case ProfileType::CACHE: return "CACHE";
        case ProfileType::LOCK: return "LOCK";
        case ProfileType::SYSCALL: return "SYSCALL";
        case ProfileType::CUSTOM: return "CUSTOM";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Profile Sample
// ============================================================================

ProfileSample::ProfileSample() : timestamp(0), type(ProfileType::CPU), value(0.0) {}

ProfileSample::ProfileSample(ProfileType t, const std::string& n, double v, const std::string& u)
    : timestamp(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count())
    , type(t), name(n), value(v), unit(u) {}

std::string ProfileSample::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"timestamp\":" << timestamp << ",";
    oss << "\"type\":\"" << ProfileTypeToString(type) << "\",";
    oss << "\"name\":\"" << name << "\",";
    oss << "\"value\":" << value << ",";
    oss << "\"unit\":\"" << unit << "\"";
    if (!metadata.empty()) {
        oss << ",";
        oss << "\"metadata\":{";
        bool first = true;
        for (const auto& [key, value] : metadata) {
            if (!first) oss << ",";
            oss << "\"" << key << "\":\"" << value << "\"";
            first = false;
        }
        oss << "}";
    }
    oss << "}";
    return oss.str();
}

// ============================================================================
// Profile Region
// ============================================================================

thread_local uint64_t ProfileRegion::enterTime_ = 0;

ProfileRegion::ProfileRegion(const std::string& n, ProfileType t)
    : name_(n), type_(t) {}

ProfileRegion::~ProfileRegion() = default;

void ProfileRegion::Enter() {
    enterTime_ = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
}

void ProfileRegion::Exit() {
    uint64_t exitTime = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    uint64_t duration = exitTime - enterTime_;
    
    totalTimeNs_ += duration;
    callCount_++;
}

double ProfileRegion::GetAverageTimeMs() const {
    uint64_t count = callCount_.load();
    if (count == 0) return 0.0;
    return (totalTimeNs_.load() / count) / 1e6;
}

// ============================================================================
// CPU Profiler
// ============================================================================

CpuProfiler::CpuProfiler(const Config& config) : config_(config) {}

CpuProfiler::~CpuProfiler() {
    Shutdown();
}

bool CpuProfiler::Initialize() {
    return true;
}

void CpuProfiler::Shutdown() {
    Stop();
}

void CpuProfiler::Start() {
    if (running_.exchange(true)) return;
    
    samples_.clear();
    samplerThread_ = std::thread(&CpuProfiler::SamplerLoop, this);
}

void CpuProfiler::Stop() {
    if (!running_.exchange(false)) return;
    
    if (samplerThread_.joinable()) {
        samplerThread_.join();
    }
}

void CpuProfiler::Pause() {
    paused_.store(true);
}

void CpuProfiler::Resume() {
    paused_.store(false);
}

void CpuProfiler::SamplerLoop() {
    while (running_) {
        if (!paused_) {
            CaptureSample();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.sampleIntervalMs));
    }
}

void CpuProfiler::CaptureSample() {
    // Platform-specific CPU sampling
#ifdef _WIN32
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        // Calculate CPU usage
        static uint64_t prevIdle = 0, prevKernel = 0, prevUser = 0;
        
        uint64_t idle = (uint64_t)idleTime.dwHighDateTime << 32 | idleTime.dwLowDateTime;
        uint64_t kernel = (uint64_t)kernelTime.dwHighDateTime << 32 | kernelTime.dwLowDateTime;
        uint64_t user = (uint64_t)userTime.dwHighDateTime << 32 | userTime.dwLowDateTime;
        
        if (prevIdle != 0) {
            uint64_t idleDiff = idle - prevIdle;
            uint64_t kernelDiff = kernel - prevKernel;
            uint64_t userDiff = user - prevUser;
            uint64_t totalDiff = kernelDiff + userDiff;
            
            double cpuPercent = 0.0;
            if (totalDiff > 0) {
                cpuPercent = 100.0 * (1.0 - (double)idleDiff / totalDiff);
            }
            
            std::lock_guard<std::mutex> lock(samplesMutex_);
            samples_.emplace_back(ProfileType::CPU, "system_cpu", cpuPercent, "percent");
        }
        
        prevIdle = idle;
        prevKernel = kernel;
        prevUser = user;
    }
#else
    // Linux implementation would go here
    std::lock_guard<std::mutex> lock(samplesMutex_);
    samples_.emplace_back(ProfileType::CPU, "system_cpu", 0.0, "percent");
#endif
}

std::vector<ProfileSample> CpuProfiler::GetSamples() const {
    std::lock_guard<std::mutex> lock(samplesMutex_);
    return samples_;
}

std::map<std::string, double> CpuProfiler::GetHotspots() const {
    std::map<std::string, double> hotspots;
    
    std::lock_guard<std::mutex> lock(samplesMutex_);
    for (const auto& sample : samples_) {
        hotspots[sample.name] += sample.value;
    }
    
    return hotspots;
}

std::map<std::string, double> CpuProfiler::GetCallTree() const {
    // Simplified call tree - would need actual stack traces
    return GetHotspots();
}

std::string CpuProfiler::ExportFlameGraph() const {
    std::ostringstream oss;
    
    std::lock_guard<std::mutex> lock(samplesMutex_);
    for (const auto& sample : samples_) {
        oss << sample.name << " " << sample.value << "\n";
    }
    
    return oss.str();
}

std::string CpuProfiler::ExportJson() const {
    std::ostringstream oss;
    oss << "[";
    
    std::lock_guard<std::mutex> lock(samplesMutex_);
    for (size_t i = 0; i < samples_.size(); ++i) {
        if (i > 0) oss << ",";
        oss << samples_[i].ToJson();
    }
    oss << "]";
    
    return oss.str();
}

// ============================================================================
// Memory Profiler
// ============================================================================

MemoryProfiler::MemoryProfiler(const Config& config) : config_(config) {}

MemoryProfiler::~MemoryProfiler() {
    Shutdown();
}

bool MemoryProfiler::Initialize() {
    return true;
}

void MemoryProfiler::Shutdown() {
    // Clean up
}

void MemoryProfiler::TrackAllocation(void* ptr, size_t size, const std::string& type,
                                     const std::string& file, uint32_t line) {
    if (!config_.trackAllocations) return;
    
    // Sample rate
    if (config_.sampleRate > 1) {
        if (++allocationCounter_ % config_.sampleRate != 0) return;
    }
    
    Allocation alloc;
    alloc.address = ptr;
    alloc.size = size;
    alloc.type = type;
    alloc.file = file;
    alloc.line = line;
    alloc.timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    
    std::lock_guard<std::mutex> lock(allocationsMutex_);
    allocations_[ptr] = alloc;
    
    totalAllocated_ += size;
    currentUsage_ += size;
    
    size_t peak = peakUsage_.load();
    while (currentUsage_ > peak && !peakUsage_.compare_exchange_weak(peak, currentUsage_.load())) {}
}

void MemoryProfiler::TrackDeallocation(void* ptr) {
    if (!config_.trackAllocations) return;
    
    std::lock_guard<std::mutex> lock(allocationsMutex_);
    auto it = allocations_.find(ptr);
    if (it != allocations_.end()) {
        totalFreed_ += it->second.size;
        currentUsage_ -= it->second.size;
        allocations_.erase(it);
    }
}

std::vector<MemoryProfiler::Allocation> MemoryProfiler::GetActiveAllocations() const {
    std::lock_guard<std::mutex> lock(allocationsMutex_);
    std::vector<Allocation> result;
    for (const auto& [ptr, alloc] : allocations_) {
        result.push_back(alloc);
    }
    return result;
}

std::map<std::string, size_t> MemoryProfiler::GetAllocationsByType() const {
    std::map<std::string, size_t> result;
    
    std::lock_guard<std::mutex> lock(allocationsMutex_);
    for (const auto& [ptr, alloc] : allocations_) {
        result[alloc.type] += alloc.size;
    }
    
    return result;
}

std::map<std::string, size_t> MemoryProfiler::GetAllocationsByFile() const {
    std::map<std::string, size_t> result;
    
    std::lock_guard<std::mutex> lock(allocationsMutex_);
    for (const auto& [ptr, alloc] : allocations_) {
        result[alloc.file] += alloc.size;
    }
    
    return result;
}

std::vector<MemoryProfiler::Allocation> MemoryProfiler::GetLeaks() const {
    std::vector<Allocation> leaks;
    
    if (!config_.detectLeaks) return leaks;
    
    std::lock_guard<std::mutex> lock(allocationsMutex_);
    for (const auto& [ptr, alloc] : allocations_) {
        leaks.push_back(alloc);
    }
    
    return leaks;
}

size_t MemoryProfiler::GetTotalAllocated() const {
    return totalAllocated_.load();
}

size_t MemoryProfiler::GetTotalFreed() const {
    return totalFreed_.load();
}

size_t MemoryProfiler::GetCurrentUsage() const {
    return currentUsage_.load();
}

size_t MemoryProfiler::GetPeakUsage() const {
    return peakUsage_.load();
}

std::string MemoryProfiler::ExportHeapDump() const {
    std::ostringstream oss;
    oss << "HEAP DUMP\n";
    oss << "=========\n\n";
    
    std::lock_guard<std::mutex> lock(allocationsMutex_);
    for (const auto& [ptr, alloc] : allocations_) {
        oss << "Address: " << ptr << "\n";
        oss << "Size: " << alloc.size << " bytes\n";
        oss << "Type: " << alloc.type << "\n";
        oss << "Location: " << alloc.file << ":" << alloc.line << "\n";
        oss << "Timestamp: " << alloc.timestamp << "\n";
        oss << "\n";
    }
    
    return oss.str();
}

std::string MemoryProfiler::ExportJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"totalAllocated\":" << GetTotalAllocated() << ",";
    oss << "\"totalFreed\":" << GetTotalFreed() << ",";
    oss << "\"currentUsage\":" << GetCurrentUsage() << ",";
    oss << "\"peakUsage\":" << GetPeakUsage() << ",";
    oss << "\"activeAllocations\":" << allocations_.size();
    oss << "}";
    return oss.str();
}

// ============================================================================
// I/O Profiler
// ============================================================================

IoProfiler::IoProfiler(const Config& config) : config_(config) {}

void IoProfiler::RecordOperation(const IoOperation& op) {
    std::lock_guard<std::mutex> lock(operationsMutex_);
    operations_.push_back(op);
    
    totalOperations_++;
    if (op.operation == "read") {
        totalBytesRead_ += op.bytesTransferred;
    } else if (op.operation == "write") {
        totalBytesWritten_ += op.bytesTransferred;
    }
}

std::vector<IoProfiler::IoOperation> IoProfiler::GetSlowOperations() const {
    std::vector<IoOperation> slow;
    
    std::lock_guard<std::mutex> lock(operationsMutex_);
    for (const auto& op : operations_) {
        uint64_t duration = op.endTime - op.startTime;
        if (duration > config_.slowIoThresholdMs * 1000000) {
            slow.push_back(op);
        }
    }
    
    return slow;
}

std::map<std::string, uint64_t> IoProfiler::GetIoByPath() const {
    std::map<std::string, uint64_t> result;
    
    std::lock_guard<std::mutex> lock(operationsMutex_);
    for (const auto& op : operations_) {
        result[op.path] += op.bytesTransferred;
    }
    
    return result;
}

std::map<std::string, double> IoProfiler::GetAverageLatencyByOperation() const {
    std::map<std::string, std::pair<uint64_t, uint64_t>> sums;
    
    std::lock_guard<std::mutex> lock(operationsMutex_);
    for (const auto& op : operations_) {
        uint64_t duration = op.endTime - op.startTime;
        auto& pair = sums[op.operation];
        pair.first += duration;
        pair.second++;
    }
    
    std::map<std::string, double> result;
    for (const auto& [op, sum] : sums) {
        if (sum.second > 0) {
            result[op] = (sum.first / sum.second) / 1e6;  // Convert to ms
        }
    }
    
    return result;
}

uint64_t IoProfiler::GetTotalOperations() const {
    return totalOperations_.load();
}

uint64_t IoProfiler::GetTotalBytesRead() const {
    return totalBytesRead_.load();
}

uint64_t IoProfiler::GetTotalBytesWritten() const {
    return totalBytesWritten_.load();
}

double IoProfiler::GetAverageLatencyMs() const {
    std::lock_guard<std::mutex> lock(operationsMutex_);
    if (operations_.empty()) return 0.0;
    
    uint64_t totalDuration = 0;
    for (const auto& op : operations_) {
        totalDuration += (op.endTime - op.startTime);
    }
    
    return (totalDuration / operations_.size()) / 1e6;
}

// ============================================================================
// GPU Profiler
// ============================================================================

GpuProfiler::GpuProfiler() = default;

GpuProfiler::~GpuProfiler() {
    Shutdown();
}

bool GpuProfiler::Initialize() {
    // Platform-specific GPU initialization
    return true;
}

void GpuProfiler::Shutdown() {
    StopSampling();
}

void GpuProfiler::StartSampling() {
    if (running_.exchange(true)) return;
    samplerThread_ = std::thread(&GpuProfiler::SamplerLoop, this);
}

void GpuProfiler::StopSampling() {
    if (!running_.exchange(false)) return;
    
    if (samplerThread_.joinable()) {
        samplerThread_.join();
    }
}

void GpuProfiler::RecordKernelExecution(const KernelExecution& kernel) {
    std::lock_guard<std::mutex> lock(kernelsMutex_);
    kernels_.push_back(kernel);
}

std::vector<GpuProfiler::GpuSample> GpuProfiler::GetSamples() const {
    std::lock_guard<std::mutex> lock(samplesMutex_);
    return samples_;
}

std::vector<GpuProfiler::KernelExecution> GpuProfiler::GetKernelExecutions() const {
    std::lock_guard<std::mutex> lock(kernelsMutex_);
    return kernels_;
}

float GpuProfiler::GetAverageUtilization() const {
    std::lock_guard<std::mutex> lock(samplesMutex_);
    if (samples_.empty()) return 0.0f;
    
    float total = 0.0f;
    for (const auto& sample : samples_) {
        total += sample.utilization;
    }
    
    return total / samples_.size();
}

float GpuProfiler::GetPeakUtilization() const {
    std::lock_guard<std::mutex> lock(samplesMutex_);
    float peak = 0.0f;
    for (const auto& sample : samples_) {
        peak = std::max(peak, sample.utilization);
    }
    return peak;
}

size_t GpuProfiler::GetPeakMemoryUsage() const {
    std::lock_guard<std::mutex> lock(samplesMutex_);
    size_t peak = 0;
    for (const auto& sample : samples_) {
        peak = std::max(peak, sample.memoryUsed);
    }
    return peak;
}

void GpuProfiler::SamplerLoop() {
    while (running_) {
        auto sample = CaptureSample();
        {
            std::lock_guard<std::mutex> lock(samplesMutex_);
            samples_.push_back(sample);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

GpuProfiler::GpuSample GpuProfiler::CaptureSample() {
    GpuSample sample;
    sample.timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    
    // Platform-specific GPU sampling would go here
    // For now, return zeros
    sample.utilization = 0.0f;
    sample.memoryUtilization = 0.0f;
    sample.memoryUsed = 0;
    sample.memoryTotal = 0;
    sample.temperature = 0.0f;
    sample.fanSpeed = 0;
    
    return sample;
}

// ============================================================================
// Cache Profiler
// ============================================================================

void CacheProfiler::RecordHit(const std::string& cacheName) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_[cacheName].hits++;
}

void CacheProfiler::RecordMiss(const std::string& cacheName) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_[cacheName].misses++;
}

void CacheProfiler::RecordEviction(const std::string& cacheName) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_[cacheName].evictions++;
}

void CacheProfiler::UpdateSize(const std::string& cacheName, uint64_t size, uint64_t capacity) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_[cacheName].size = size;
    stats_[cacheName].capacity = capacity;
}

CacheProfiler::CacheStats CacheProfiler::GetStats(const std::string& cacheName) const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    auto it = stats_.find(cacheName);
    if (it != stats_.end()) {
        return it->second;
    }
    return CacheStats{};
}

std::map<std::string, CacheProfiler::CacheStats> CacheProfiler::GetAllStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

double CacheProfiler::GetHitRate(const std::string& cacheName) const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    auto it = stats_.find(cacheName);
    if (it == stats_.end()) return 0.0;
    
    const auto& stats = it->second;
    uint64_t total = stats.hits + stats.misses;
    if (total == 0) return 0.0;
    
    return 100.0 * stats.hits / total;
}

// ============================================================================
// Lock Profiler
// ============================================================================

void LockProfiler::RecordAcquire(const std::string& lockName, uint64_t waitTimeNs) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    auto& stats = stats_[lockName];
    stats.name = lockName;
    stats.acquireCount++;
    if (waitTimeNs > 0) {
        stats.contentionCount++;
        stats.totalWaitTimeNs += waitTimeNs;
        stats.maxWaitTimeNs = std::max(stats.maxWaitTimeNs, waitTimeNs);
    }
    stats.currentHolders++;
}

void LockProfiler::RecordRelease(const std::string& lockName) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    auto it = stats_.find(lockName);
    if (it != stats_.end() && it->second.currentHolders > 0) {
        it->second.currentHolders--;
    }
}

LockProfiler::LockStats LockProfiler::GetStats(const std::string& lockName) const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    auto it = stats_.find(lockName);
    if (it != stats_.end()) {
        return it->second;
    }
    return LockStats{};
}

std::vector<LockProfiler::LockStats> LockProfiler::GetHotLocks() const {
    std::vector<LockStats> result;
    
    std::lock_guard<std::mutex> lock(statsMutex_);
    for (const auto& [name, stats] : stats_) {
        result.push_back(stats);
    }
    
    // Sort by contention
    std::sort(result.begin(), result.end(),
              [](const LockStats& a, const LockStats& b) {
                  return a.contentionCount > b.contentionCount;
              });
    
    return result;
}

// ============================================================================
// Performance Profiler
// ============================================================================

PerformanceProfiler::PerformanceProfiler(const Config& config) : config_(config) {
    if (config_.enableCpuProfiling) {
        cpuProfiler_ = std::make_unique<CpuProfiler>();
    }
    if (config_.enableMemoryProfiling) {
        memoryProfiler_ = std::make_unique<MemoryProfiler>();
    }
    if (config_.enableIoProfiling) {
        ioProfiler_ = std::make_unique<IoProfiler>();
    }
    if (config_.enableGpuProfiling) {
        gpuProfiler_ = std::make_unique<GpuProfiler>();
    }
    if (config_.enableCacheProfiling) {
        cacheProfiler_ = std::make_unique<CacheProfiler>();
    }
    if (config_.enableLockProfiling) {
        lockProfiler_ = std::make_unique<LockProfiler>();
    }
}

PerformanceProfiler::~PerformanceProfiler() {
    Shutdown();
}

bool PerformanceProfiler::Initialize() {
    bool success = true;
    
    if (cpuProfiler_) success &= cpuProfiler_->Initialize();
    if (memoryProfiler_) success &= memoryProfiler_->Initialize();
    if (ioProfiler_) success &= ioProfiler_->Initialize();
    if (gpuProfiler_) success &= gpuProfiler_->Initialize();
    
    return success;
}

void PerformanceProfiler::Shutdown() {
    StopProfiling();
    
    if (cpuProfiler_) cpuProfiler_->Shutdown();
    if (memoryProfiler_) memoryProfiler_->Shutdown();
    if (ioProfiler_) ioProfiler_->Shutdown();
    if (gpuProfiler_) gpuProfiler_->Shutdown();
}

void PerformanceProfiler::StartProfiling() {
    if (profiling_.exchange(true)) return;
    
    if (cpuProfiler_) cpuProfiler_->Start();
    if (gpuProfiler_) gpuProfiler_->StartSampling();
}

void PerformanceProfiler::StopProfiling() {
    if (!profiling_.exchange(false)) return;
    
    if (cpuProfiler_) cpuProfiler_->Stop();
    if (gpuProfiler_) gpuProfiler_->StopSampling();
}

void PerformanceProfiler::PauseProfiling() {
    if (cpuProfiler_) cpuProfiler_->Pause();
}

void PerformanceProfiler::ResumeProfiling() {
    if (cpuProfiler_) cpuProfiler_->Resume();
}

bool PerformanceProfiler::IsProfiling() const {
    return profiling_.load();
}

CpuProfiler* PerformanceProfiler::GetCpuProfiler() {
    return cpuProfiler_.get();
}

MemoryProfiler* PerformanceProfiler::GetMemoryProfiler() {
    return memoryProfiler_.get();
}

IoProfiler* PerformanceProfiler::GetIoProfiler() {
    return ioProfiler_.get();
}

GpuProfiler* PerformanceProfiler::GetGpuProfiler() {
    return gpuProfiler_.get();
}

CacheProfiler* PerformanceProfiler::GetCacheProfiler() {
    return cacheProfiler_.get();
}

LockProfiler* PerformanceProfiler::GetLockProfiler() {
    return lockProfiler_.get();
}

void PerformanceProfiler::BeginRegion(const std::string& name, ProfileType type) {
    std::lock_guard<std::mutex> lock(regionsMutex_);
    auto it = regions_.find(name);
    if (it == regions_.end()) {
        auto region = std::make_unique<ProfileRegion>(name, type);
        region->Enter();
        regions_[name] = std::move(region);
    } else {
        it->second->Enter();
    }
}

void PerformanceProfiler::EndRegion(const std::string& name) {
    std::lock_guard<std::mutex> lock(regionsMutex_);
    auto it = regions_.find(name);
    if (it != regions_.end()) {
        it->second->Exit();
    }
}

std::string PerformanceProfiler::GenerateReport() const {
    std::ostringstream oss;
    oss << "Performance Profile Report\n";
    oss << "==========================\n\n";
    
    // CPU stats
    if (cpuProfiler_) {
        oss << "CPU Profile:\n";
        auto hotspots = cpuProfiler_->GetHotspots();
        for (const auto& [name, value] : hotspots) {
            oss << "  " << name << ": " << value << "%\n";
        }
        oss << "\n";
    }
    
    // Memory stats
    if (memoryProfiler_) {
        oss << "Memory Profile:\n";
        oss << "  Current Usage: " << memoryProfiler_->GetCurrentUsage() << " bytes\n";
        oss << "  Peak Usage: " << memoryProfiler_->GetPeakUsage() << " bytes\n";
        oss << "\n";
    }
    
    // Region stats
    oss << "Profiled Regions:\n";
    std::lock_guard<std::mutex> lock(regionsMutex_);
    for (const auto& [name, region] : regions_) {
        oss << "  " << name << ": " << region->GetCallCount() << " calls, ";
        oss << region->GetAverageTimeMs() << " ms avg\n";
    }
    
    return oss.str();
}

std::vector<std::string> PerformanceProfiler::GetBottlenecks() const {
    std::vector<std::string> bottlenecks;
    
    // Check for high CPU usage
    if (cpuProfiler_) {
        auto hotspots = cpuProfiler_->GetHotspots();
        for (const auto& [name, value] : hotspots) {
            if (value > 50.0) {
                bottlenecks.push_back("High CPU usage in " + name + ": " + 
                                    std::to_string(value) + "%");
            }
        }
    }
    
    // Check for lock contention
    if (lockProfiler_) {
        auto hotLocks = lockProfiler_->GetHotLocks();
        for (const auto& stats : hotLocks) {
            if (stats.contentionCount > 100) {
                bottlenecks.push_back("Lock contention in " + stats.name + ": " +
                                    std::to_string(stats.contentionCount) + " contentions");
            }
        }
    }
    
    return bottlenecks;
}

std::map<std::string, std::string> PerformanceProfiler::GetRecommendations() const {
    std::map<std::string, std::string> recommendations;
    
    auto bottlenecks = GetBottlenecks();
    for (const auto& bottleneck : bottlenecks) {
        if (bottleneck.find("CPU") != std::string::npos) {
            recommendations[bottleneck] = "Consider optimizing hot paths or parallelizing work";
        } else if (bottleneck.find("Lock") != std::string::npos) {
            recommendations[bottleneck] = "Consider using lock-free data structures or reducing critical section size";
        }
    }
    
    return recommendations;
}

void PerformanceProfiler::ExportToChromeTracing(const std::string& filepath) const {
    // Chrome trace format export
    std::ofstream file(filepath);
    file << "[\n";
    
    bool first = true;
    if (cpuProfiler_) {
        auto samples = cpuProfiler_->GetSamples();
        for (const auto& sample : samples) {
            if (!first) file << ",\n";
            file << "{\"name\":\"" << sample.name << "\",";
            file << "\"ph\":\"C\",\"ts\":" << sample.timestamp << ",";
            file << "\"args\":{\"value\":" << sample.value << "}}";
            first = false;
        }
    }
    
    file << "\n]\n";
}

void PerformanceProfiler::ExportToFlameGraph(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (cpuProfiler_) {
        file << cpuProfiler_->ExportFlameGraph();
    }
}

std::string PerformanceProfiler::ExportJson() const {
    std::ostringstream oss;
    oss << "{";
    
    if (cpuProfiler_) {
        oss << "\"cpu\":" << cpuProfiler_->ExportJson() << ",";
    }
    if (memoryProfiler_) {
        oss << "\"memory\":" << memoryProfiler_->ExportJson() << ",";
    }
    
    // Regions
    oss << "\"regions\":{";
    std::lock_guard<std::mutex> lock(regionsMutex_);
    bool first = true;
    for (const auto& [name, region] : regions_) {
        if (!first) oss << ",";
        oss << "\"" << name << "\":{";
        oss << "\"calls\":" << region->GetCallCount() << ",";
        oss << "\"totalMs\":" << (region->GetTotalTimeNs() / 1e6) << ",";
        oss << "\"avgMs\":" << region->GetAverageTimeMs();
        oss << "}";
        first = false;
    }
    oss << "}";
    
    oss << "}";
    return oss.str();
}

std::string PerformanceProfiler::GetStatusJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"profiling\":" << (profiling_ ? "true" : "false") << ",";
    oss << "\"cpuEnabled\":" << (config_.enableCpuProfiling ? "true" : "false") << ",";
    oss << "\"memoryEnabled\":" << (config_.enableMemoryProfiling ? "true" : "false") << ",";
    oss << "\"ioEnabled\":" << (config_.enableIoProfiling ? "true" : "false") << ",";
    oss << "\"gpuEnabled\":" << (config_.enableGpuProfiling ? "true" : "false") << ",";
    oss << "\"cacheEnabled\":" << (config_.enableCacheProfiling ? "true" : "false") << ",";
    oss << "\"lockEnabled\":" << (config_.enableLockProfiling ? "true" : "false");
    oss << "}";
    return oss.str();
}

// ============================================================================
// Scoped Region
// ============================================================================

PerformanceProfiler::ScopedRegion::ScopedRegion(PerformanceProfiler* profiler,
                                                const std::string& name,
                                                ProfileType type)
    : profiler_(profiler), name_(name) {
    if (profiler_) {
        profiler_->BeginRegion(name_, type);
    }
}

PerformanceProfiler::ScopedRegion::~ScopedRegion() {
    if (profiler_) {
        profiler_->EndRegion(name_);
    }
}

} // namespace Performance
