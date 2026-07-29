// ============================================================================
// FlameGraphProfiler.cpp - Flame Graph & Memory Profiler Implementation
// ============================================================================

#include "FlameGraphProfiler.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <thread>

namespace Sovereign {

FlameGraphProfiler::FlameGraphProfiler() = default;
FlameGraphProfiler::~FlameGraphProfiler() { Shutdown(); }

bool FlameGraphProfiler::Initialize(size_t maxSamples) {
    maxSamples_ = maxSamples;
    samples_.reserve(maxSamples_);
    return true;
}

void FlameGraphProfiler::Shutdown() { Stop(); samples_.clear(); }

void FlameGraphProfiler::Start() {
    if (running_.exchange(true)) return;
    profilerThread_ = std::thread(&FlameGraphProfiler::ProfilerLoop, this);
}

void FlameGraphProfiler::Stop() {
    if (!running_.exchange(false)) return;
    if (profilerThread_.joinable()) profilerThread_.join();
}

void FlameGraphProfiler::ProfilerLoop() {
    while (running_.load()) {
        ProfilerSample sample;
        sample.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        sample.threadId = GetCurrentThreadId();
        sample.cpuCycles = __rdtsc();
        sample.memoryBytes = 0;
        
        // Capture stack trace (simplified)
        sample.stackTrace.push_back(reinterpret_cast<uint64_t>(&ProfilerLoop));
        
        AddSample(sample);
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
}

void FlameGraphProfiler::AddSample(const ProfilerSample& sample) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (samples_.size() >= maxSamples_) return;
    samples_.push_back(sample);
    stats_.totalSamples++;
}

FlameGraph FlameGraphProfiler::BuildFlameGraph() const {
    std::lock_guard<std::mutex> lock(mutex_);
    FlameGraph graph;
    graph.totalTime = 0;
    graph.totalCalls = samples_.size();
    
    for (const auto& sample : samples_) {
        graph.totalTime += sample.cpuCycles;
    }
    
    return graph;
}

bool FlameGraphProfiler::ExportToSVG(const std::string& path) {
    std::ofstream file(path);
    if (!file) return false;
    
    auto graph = BuildFlameGraph();
    
    file << "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1200 800\">\n";
    file << "<rect width=\"1200\" height=\"800\" fill=\"#1e1e1e\"/>\n";
    file << "<text x=\"10\" y=\"20\" fill=\"white\" font-family=\"monospace\" font-size=\"14\">";
    file << "Flame Graph - " << graph.totalCalls << " samples, " << graph.totalTime << " cycles";
    file << "</text>\n";
    file << "</svg>\n";
    
    return true;
}

bool FlameGraphProfiler::ExportToJSON(const std::string& path) {
    std::ofstream file(path);
    if (!file) return false;
    
    file << "{\n  \"samples\": [\n";
    bool first = true;
    for (const auto& s : samples_) {
        if (!first) file << ",\n";
        first = false;
        file << "    {\"timestamp\": " << s.timestamp << ", \"threadId\": " << s.threadId << "}";
    }
    file << "\n  ]\n}\n";
    return true;
}

// ============================================================
// MemoryProfiler
// ============================================================

MemoryProfiler::MemoryProfiler() = default;
MemoryProfiler::~MemoryProfiler() { Shutdown(); }

bool MemoryProfiler::Initialize() { return true; }
void MemoryProfiler::Shutdown() { Stop(); allocations_.clear(); }

void MemoryProfiler::Start() {
    if (running_.exchange(true)) return;
    profilerThread_ = std::thread(&MemoryProfiler::ProfilerLoop, this);
}

void MemoryProfiler::Stop() {
    if (!running_.exchange(false)) return;
    if (profilerThread_.joinable()) profilerThread_.join();
}

void MemoryProfiler::RecordAllocation(void* ptr, size_t size, const std::string& tag) {
    std::lock_guard<std::mutex> lock(mutex_);
    AllocRecord rec;
    rec.ptr = ptr;
    rec.size = size;
    rec.tag = tag.empty() ? "unknown" : tag;
    rec.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    allocations_[ptr] = rec;
    stats_.totalAllocations++;
    stats_.currentAllocations++;
    stats_.currentMemory += size;
    stats_.peakMemory = std::max(stats_.peakMemory, stats_.currentMemory);
}

void MemoryProfiler::RecordDeallocation(void* ptr) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = allocations_.find(ptr);
    if (it == allocations_.end()) return;
    stats_.currentMemory -= it->second.size;
    stats_.currentAllocations--;
    stats_.totalDeallocations++;
    allocations_.erase(it);
}

MemoryProfiler::MemorySnapshot MemoryProfiler::GetSnapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    MemorySnapshot snap;
    snap.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    snap.currentUsage = stats_.currentMemory;
    snap.peakUsage = stats_.peakMemory;
    snap.allocationCount = stats_.totalAllocations;
    snap.deallocationCount = stats_.totalDeallocations;
    
    for (const auto& [ptr, rec] : allocations_) {
        snap.tagBreakdown[rec.tag] += rec.size;
    }
    
    return snap;
}

void MemoryProfiler::ProfilerLoop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

bool MemoryProfiler::ExportToJSON(const std::string& path) {
    auto snap = GetSnapshot();
    std::ofstream file(path);
    if (!file) return false;
    
    file << "{\n";
    file << "  \"timestamp\": " << snap.timestamp << ",\n";
    file << "  \"currentUsage\": " << snap.currentUsage << ",\n";
    file << "  \"peakUsage\": " << snap.peakUsage << ",\n";
    file << "  \"allocations\": " << snap.allocationCount << ",\n";
    file << "  \"deallocations\": " << snap.deallocationCount << "\n";
    file << "}\n";
    return true;
}

} // namespace Sovereign
