#include "profiler.h"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

Profiler::Profiler()
    : m_isProfiling(false)
{
    m_startTime = std::chrono::steady_clock::now();
}

void Profiler::startProfiling() {
    m_isProfiling = true;
    m_startTime = std::chrono::steady_clock::now();
    m_phaseStarts.clear();
}

void Profiler::stopProfiling() {
    m_isProfiling = false;
}

void Profiler::markPhaseStart(const std::string& phaseName) {
    if (!m_isProfiling) return;
    m_phaseStarts[phaseName] = std::chrono::steady_clock::now();
}

void Profiler::markPhaseEnd(const std::string& phaseName) {
    if (!m_isProfiling) return;
    m_phaseStarts.erase(phaseName);
}

void Profiler::recordBatchCompleted(int sampleCount, int tokenCount) {
    if (!m_isProfiling) return;
    (void)sampleCount;
    (void)tokenCount;
}

void Profiler::recordMemoryAllocation(size_t bytes) {
    if (!m_isProfiling) return;
    m_memoryAllocated += bytes;
}

void Profiler::recordMemoryDeallocation(size_t bytes) {
    if (!m_isProfiling) return;
    if (bytes > m_memoryAllocated) m_memoryAllocated = 0;
    else m_memoryAllocated -= bytes;
}

void Profiler::updateGpuMetrics(float gpuUsagePercent, float gpuMemoryMB) {
    (void)gpuUsagePercent;
    (void)gpuMemoryMB;
}

Profiler::ProfileSnapshot Profiler::getCurrentSnapshot() const {
    ProfileSnapshot snap;
    snap.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    snap.memoryUsageMB = static_cast<float>(m_memoryAllocated) / (1024.0f * 1024.0f);
    return snap;
}

json Profiler::getProfilingReport() const {
    json report;
    report["profiling_active"] = m_isProfiling;
    report["memory_allocated_bytes"] = m_memoryAllocated;
    report["memory_allocated_mb"] = static_cast<double>(m_memoryAllocated) / (1024.0 * 1024.0);
    return report;
}

bool Profiler::exportReport(const std::string& filePath) const {
    std::ofstream ofs(filePath);
    if (!ofs) return false;
    ofs << getProfilingReport().dump(2);
    return true;
}