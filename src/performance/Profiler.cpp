#include "rawrxd/performance/Profiler.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace rawrxd {
namespace performance {

// ProfileScope implementation
ProfileScope::ProfileScope(const std::string& name, const std::string& category)
    : name_(name), category_(category), start_(std::chrono::high_resolution_clock::now()), ended_(false) {
}

ProfileScope::~ProfileScope() {
    if (!ended_) {
        End();
    }
}

void ProfileScope::End() {
    if (ended_) return;
    
    auto end = std::chrono::high_resolution_clock::now();
    float durationMs = std::chrono::duration<float, std::milli>(end - start_).count();
    
    // Update profiler data
    auto& profiler = Profiler::GetInstance();
    if (profiler.IsProfiling()) {
        profiler.BeginRegion(name_, category_);
        profiler.EndRegion(name_);
    }
    
    ended_ = true;
}

// Profiler implementation
Profiler& Profiler::GetInstance() {
    static Profiler instance;
    return instance;
}

Profiler::Profiler() = default;

Profiler::~Profiler() {
    if (profiling_) {
        StopProfiling();
    }
}

void Profiler::StartProfiling(const std::string& sessionName) {
    sessionName_ = sessionName;
    sessionStart_ = std::chrono::high_resolution_clock::now();
    profiling_ = true;
    data_.clear();
}

void Profiler::StopProfiling() {
    profiling_ = false;
}

void Profiler::BeginRegion(const std::string& name, const std::string& category) {
    if (!profiling_) return;
    
    ProfileData& profile = data_[name];
    profile.name = name;
    profile.category = category;
    profile.startTime = std::chrono::high_resolution_clock::now();
    activeRegions_.push_back(name);
}

void Profiler::EndRegion(const std::string& name) {
    if (!profiling_) return;
    
    auto it = data_.find(name);
    if (it == data_.end()) return;
    
    auto endTime = std::chrono::high_resolution_clock::now();
    float durationMs = std::chrono::duration<float, std::milli>(
        endTime - it->second.startTime).count();
    
    UpdateStats(it->second, durationMs);
    
    // Remove from active regions
    auto activeIt = std::find(activeRegions_.begin(), activeRegions_.end(), name);
    if (activeIt != activeRegions_.end()) {
        activeRegions_.erase(activeIt);
    }
}

void Profiler::UpdateStats(ProfileData& data, float durationMs) {
    data.durationMs = durationMs;
    data.callCount++;
    data.totalTimeMs += durationMs;
    
    if (data.callCount == 1) {
        data.minTimeMs = durationMs;
        data.maxTimeMs = durationMs;
    } else {
        data.minTimeMs = std::min(data.minTimeMs, durationMs);
        data.maxTimeMs = std::max(data.maxTimeMs, durationMs);
    }
    
    data.avgTimeMs = data.totalTimeMs / data.callCount;
}

std::vector<ProfileData> Profiler::GetResults() const {
    std::vector<ProfileData> results;
    for (const auto& pair : data_) {
        results.push_back(pair.second);
    }
    return results;
}

ProfileData Profiler::GetResult(const std::string& name) const {
    auto it = data_.find(name);
    if (it != data_.end()) {
        return it->second;
    }
    return ProfileData();
}

std::unordered_map<std::string, ProfileData> Profiler::GetResultsByCategory() const {
    std::unordered_map<std::string, ProfileData> categoryData;
    
    for (const auto& pair : data_) {
        const auto& profile = pair.second;
        auto& catProfile = categoryData[profile.category];
        catProfile.category = profile.category;
        catProfile.callCount += profile.callCount;
        catProfile.totalTimeMs += profile.totalTimeMs;
        catProfile.minTimeMs = std::min(catProfile.minTimeMs, profile.minTimeMs);
        catProfile.maxTimeMs = std::max(catProfile.maxTimeMs, profile.maxTimeMs);
    }
    
    // Calculate averages
    for (auto& pair : categoryData) {
        if (pair.second.callCount > 0) {
            pair.second.avgTimeMs = pair.second.totalTimeMs / pair.second.callCount;
        }
    }
    
    return categoryData;
}

std::string Profiler::ExportToJSON() const {
    std::stringstream json;
    json << "{\n";
    json << "  \"session\": \"" << sessionName_ << "\",\n";
    json << "  \"regions\": [\n";
    
    bool first = true;
    for (const auto& pair : data_) {
        const auto& data = pair.second;
        if (!first) json << ",\n";
        first = false;
        
        json << "    {\n";
        json << "      \"name\": \"" << data.name << "\",\n";
        json << "      \"category\": \"" << data.category << "\",\n";
        json << "      \"callCount\": " << data.callCount << ",\n";
        json << "      \"totalTimeMs\": " << data.totalTimeMs << ",\n";
        json << "      \"avgTimeMs\": " << data.avgTimeMs << ",\n";
        json << "      \"minTimeMs\": " << data.minTimeMs << ",\n";
        json << "      \"maxTimeMs\": " << data.maxTimeMs << "\n";
        json << "    }";
    }
    
    json << "\n  ]\n";
    json << "}";
    return json.str();
}

std::string Profiler::ExportToChromeTrace() const {
    std::stringstream trace;
    trace << "[\n";
    
    // Chrome trace format: [{"name": "...", "ph": "B", "ts": ..., "pid": ..., "tid": ...}, ...]
    // For simplicity, just output the profile data
    bool first = true;
    for (const auto& pair : data_) {
        const auto& data = pair.second;
        if (!first) trace << ",\n";
        first = false;
        
        trace << "  {\"name\": \"" << data.name << "\", ";
        trace << "\"cat\": \"" << data.category << "\", ";
        trace << "\"ph\": \"X\", ";  // Complete event
        trace << "\"ts\": 0, ";
        trace << "\"dur\": " << static_cast<int>(data.totalTimeMs * 1000) << ", ";
        trace << "\"pid\": 1, ";
        trace << "\"tid\": 1}";
    }
    
    trace << "\n]";
    return trace.str();
}

std::string Profiler::ExportToMarkdown() const {
    std::stringstream md;
    md << "# Profile Report: " << sessionName_ << "\n\n";
    md << "| Region | Category | Calls | Total (ms) | Avg (ms) | Min (ms) | Max (ms) |\n";
    md << "|--------|----------|-------|------------|----------|----------|----------|\n";
    
    for (const auto& pair : data_) {
        const auto& data = pair.second;
        md << "| " << data.name << " | ";
        md << data.category << " | ";
        md << data.callCount << " | ";
        md << std::fixed << std::setprecision(2);
        md << data.totalTimeMs << " | ";
        md << data.avgTimeMs << " | ";
        md << data.minTimeMs << " | ";
        md << data.maxTimeMs << " |\n";
    }
    
    return md.str();
}

void Profiler::Reset() {
    data_.clear();
    activeRegions_.clear();
}

// MemoryProfiler implementation
size_t MemoryProfiler::GetCurrentUsage() {
    // Platform-specific implementation would go here
    // For now, return 0
    return 0;
}

size_t MemoryProfiler::GetPeakUsage() {
    // Platform-specific implementation would go here
    return 0;
}

void MemoryProfiler::ResetPeak() {
    // Platform-specific implementation would go here
}

std::unordered_map<void*, MemoryProfiler::AllocationInfo> MemoryProfiler::GetActiveAllocations() {
    // Would track allocations
    return {};
}

std::string MemoryProfiler::GetLeakReport() {
    auto allocations = GetActiveAllocations();
    if (allocations.empty()) {
        return "No memory leaks detected.";
    }
    
    std::stringstream report;
    report << "Memory Leak Report:\n";
    report << allocations.size() << " allocations not freed:\n";
    
    for (const auto& pair : allocations) {
        const auto& info = pair.second;
        report << "  " << info.size << " bytes at " << info.file << ":" << info.line << "\n";
    }
    
    return report.str();
}

// GPUProfiler implementation
bool GPUProfiler::IsAvailable() {
    // Would check for GPU availability
    return false;
}

float GPUProfiler::GetUtilization() {
    return 0.0f;
}

size_t GPUProfiler::GetMemoryUsed() {
    return 0;
}

size_t GPUProfiler::GetMemoryTotal() {
    return 0;
}

float GPUProfiler::GetTemperature() {
    return 0.0f;
}

} // namespace performance
} // namespace rawrxd
