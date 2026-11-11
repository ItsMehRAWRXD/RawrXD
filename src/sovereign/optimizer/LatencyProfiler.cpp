// ============================================================================
// LatencyProfiler.cpp - Real-time Latency Profiler Implementation
// ============================================================================

#include "LatencyProfiler.hpp"
#include <cstring>
#include <fstream>
#include <algorithm>
#include <iostream>
#include <thread>
#include <chrono>

namespace Sovereign {

LatencyProfiler::LatencyProfiler() = default;
LatencyProfiler::~LatencyProfiler() {
    Shutdown();
}

bool LatencyProfiler::Initialize(const ProfilerConfig& config) {
    config_ = config;
    samples_.reserve(config_.maxSamples);
    initialized_ = true;
    return true;
}

void LatencyProfiler::Shutdown() {
    Stop();
    initialized_ = false;
}

void LatencyProfiler::Start() {
    if (running_.exchange(true)) return;
    profilerThread_ = std::thread(&LatencyProfiler::ProfilerLoop, this);
}

void LatencyProfiler::Stop() {
    if (!running_.exchange(false)) return;
    if (profilerThread_.joinable()) profilerThread_.join();
}

void LatencyProfiler::ProfilerLoop() {
    while (running_.load()) {
        ProfilerSample sample;
        sample.timestamp = __rdtsc();
        sample.cycles = 0;
        sample.threadId = GetCurrentThreadId();
        sample.cpuId = GetCurrentProcessorNumber();
        sample.cacheMisses = 0;
        sample.branchMispredicts = 0;
        
        AddSample(sample);
        
        std::this_thread::sleep_for(std::chrono::microseconds(config_.sampleIntervalUs));
    }
}

void LatencyProfiler::AddSample(const ProfilerSample& sample) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (samples_.size() >= config_.maxSamples) return;
    samples_.push_back(sample);
    
    ProcessSample(sample);
}

void LatencyProfiler::ProcessSample(const ProfilerSample& sample) {
    // Update hot function statistics
    auto& func = hotFunctions_[sample.address];
    
    if (func.name.empty() && symbolResolver_) {
        func.name = symbolResolver_(sample.address);
    }
    
    func.address = sample.address;
    func.totalCycles += sample.cycles;
    func.callCount++;
    func.avgCycles = func.totalCycles / func.callCount;
    func.cacheMisses += sample.cacheMisses;
    func.branchMispredicts += sample.branchMispredicts;
    func.hotness = CalculateHotness(func);
}

std::vector<HotFunction> LatencyProfiler::GetHotFunctions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<HotFunction> result;
    for (const auto& [addr, func] : hotFunctions_) {
        if (func.hotness >= config_.hotnessThreshold) {
            result.push_back(func);
        }
    }
    
    std::sort(result.begin(), result.end(), 
        [](const HotFunction& a, const HotFunction& b) {
            return a.hotness > b.hotness;
        });
    
    return result;
}

double LatencyProfiler::CalculateHotness(const HotFunction& func) const {
    if (func.callCount == 0) return 0.0;
    
    double cycleScore = std::min(1.0, func.avgCycles / 10000.0);
    double cacheScore = std::min(1.0, func.cacheMisses / 1000.0);
    double branchScore = std::min(1.0, func.branchMispredicts / 100.0);
    double callScore = std::min(1.0, func.callCount / 1000.0);
    
    return (cycleScore * 0.4 + cacheScore * 0.2 + branchScore * 0.1 + callScore * 0.3);
}

void LatencyProfiler::Export(const std::string& path) {
    std::ofstream file(path);
    if (!file) return;
    
    auto hot = GetHotFunctions();
    file << "Hot Functions Report\n";
    file << "====================\n\n";
    
    for (const auto& func : hot) {
        file << func.name << "\n";
        file << "  Address: 0x" << std::hex << func.address << std::dec << "\n";
        file << "  Hotness: " << (func.hotness * 100.0) << "%\n";
        file << "  Calls: " << func.callCount << "\n";
        file << "  Avg Cycles: " << func.avgCycles << "\n";
        file << "  Cache Misses: " << func.cacheMisses << "\n";
        file << "  Branch Mispredicts: " << func.branchMispredicts << "\n\n";
    }
}

// ============================================================
// CacheLineAligner
// ============================================================

CacheLineAligner::CacheLineAligner() = default;
CacheLineAligner::~CacheLineAligner() = default;

void* CacheLineAligner::AlignAllocate(size_t size, size_t alignment) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t totalSize = size + alignment + sizeof(void*);
    void* raw = malloc(totalSize);
    if (!raw) return nullptr;
    
    void* aligned = reinterpret_cast<void*>(
        (reinterpret_cast<uintptr_t>(raw) + alignment + sizeof(void*)) & ~(alignment - 1));
    
    // Store original pointer for free
    reinterpret_cast<void**>(aligned)[-1] = raw;
    
    stats_.totalAllocated += size;
    stats_.totalWasted += reinterpret_cast<uintptr_t>(aligned) - reinterpret_cast<uintptr_t>(raw);
    stats_.allocations++;
    
    return aligned;
}

void CacheLineAligner::AlignFree(void* ptr) {
    if (!ptr) return;
    void* raw = reinterpret_cast<void**>(ptr)[-1];
    free(raw);
}

bool CacheLineAligner::IsAligned(void* ptr, size_t alignment) const {
    return (reinterpret_cast<uintptr_t>(ptr) & (alignment - 1)) == 0;
}

void* CacheLineAligner::AlignPointer(void* ptr, size_t alignment) const {
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    uintptr_t aligned = (addr + alignment - 1) & ~(alignment - 1);
    return reinterpret_cast<void*>(aligned);
}

void CacheLineAligner::ResetStats() {
    stats_ = AlignmentStats{};
}

// ============================================================
// HeuristicPruner
// ============================================================

HeuristicPruner::HeuristicPruner() = default;
HeuristicPruner::~HeuristicPruner() = default;

void HeuristicPruner::AddHeuristic(const std::string& name, std::function<double()> heuristic) {
    std::lock_guard<std::mutex> lock(mutex_);
    heuristics_[name] = {name, heuristic, 1.0};
}

void HeuristicPruner::RemoveHeuristic(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    heuristics_.erase(name);
}

double HeuristicPruner::Evaluate(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = heuristics_.find(name);
    if (it != heuristics_.end() && it->second.func) {
        return it->second.func() * it->second.weight;
    }
    return 0.0;
}

std::vector<std::pair<std::string, double>> HeuristicPruner::EvaluateAll() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<std::string, double>> results;
    
    for (const auto& [name, heuristic] : heuristics_) {
        if (heuristic.func) {
            results.push_back({name, heuristic.func() * heuristic.weight});
        }
    }
    
    std::sort(results.begin(), results.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    return results;
}

bool HeuristicPruner::ShouldPrune(const std::string& name, double threshold) const {
    return Evaluate(name) < threshold;
}

void HeuristicPruner::PruneBelow(double threshold) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = heuristics_.begin();
    while (it != heuristics_.end()) {
        if (it->second.func && (it->second.func() * it->second.weight) < threshold) {
            it = heuristics_.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================
// InstructionTracer
// ============================================================

InstructionTracer::InstructionTracer() = default;
InstructionTracer::~InstructionTracer() = default;

bool InstructionTracer::Initialize() { return true; }
void InstructionTracer::Shutdown() { StopTracing(); }

void InstructionTracer::StartTracing(uint64_t address, size_t size) {
    tracing_ = true;
}

void InstructionTracer::StopTracing() {
    tracing_ = false;
}

std::vector<InstructionTracer::TraceEntry> InstructionTracer::GetTrace() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return trace_;
}

void InstructionTracer::ClearTrace() {
    std::lock_guard<std::mutex> lock(mutex_);
    trace_.clear();
}

void InstructionTracer::ExportTrace(const std::string& path) {
    std::ofstream file(path);
    if (!file) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : trace_) {
        file << "0x" << std::hex << entry.address << std::dec << ","
             << entry.length << ","
             << entry.count << ","
             << entry.totalCycles << "\n";
    }
}

// ============================================================
// HotPathJIT
// ============================================================

HotPathJIT::HotPathJIT() = default;
HotPathJIT::~HotPathJIT() {
    Shutdown();
}

bool HotPathJIT::Initialize() {
    // Allocate code cache (64MB)
    codeCacheSize_ = 64ULL << 20;
    codeCache_ = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, codeCacheSize_, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    
    if (!codeCache_) return false;
    codeCacheOffset_ = 0;
    return true;
}

void HotPathJIT::Shutdown() {
    if (codeCache_) {
        VirtualFree(codeCache_, 0, MEM_RELEASE);
        codeCache_ = nullptr;
    }
    compiledCode_.clear();
}

bool HotPathJIT::Compile(const HotFunction& func) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (compiledCode_.find(func.address) != compiledCode_.end()) {
        stats_.cacheHits++;
        return true;
    }
    
    // In production: actual JIT compilation
    // For now, allocate space in code cache
    size_t codeSize = 4096; // Placeholder
    if (codeCacheOffset_ + codeSize > codeCacheSize_) return false;
    
    void* codePtr = codeCache_ + codeCacheOffset_;
    codeCacheOffset_ += codeSize;
    
    compiledCode_[func.address] = codePtr;
    stats_.compilations++;
    stats_.codeSize += codeSize;
    
    return true;
}

bool HotPathJIT::IsCompiled(uint64_t address) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return compiledCode_.find(address) != compiledCode_.end();
}

void* HotPathJIT::GetCompiledCode(uint64_t address) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = compiledCode_.find(address);
    return it != compiledCode_.end() ? it->second : nullptr;
}

HotPathJIT::JITStats HotPathJIT::GetStats() const {
    return stats_;
}

} // namespace Sovereign
