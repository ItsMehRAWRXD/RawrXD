// ============================================================================
// MemoryPressureInjector.cpp — Memory Exhaustion Simulation Implementation
// ============================================================================

#include "MemoryPressureInjector.hpp"
#include <iostream>
#include <thread>
#include <chrono>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Memory Pressure Injector Implementation
// ============================================================================
MemoryPressureInjector::MemoryPressureInjector() = default;

MemoryPressureInjector::~MemoryPressureInjector() {
    shutdown();
}

bool MemoryPressureInjector::initialize() {
    return true;
}

void MemoryPressureInjector::shutdown() {
    releaseAllPressure();
    if (m_pressureThread.joinable()) {
        m_pressureActive.store(false);
        m_pressureThread.join();
    }
}

FaultInjectionResult MemoryPressureInjector::inject() {
    switch (m_pressureMode) {
        case PressureMode::GRADUAL:
            return injectGradualPressure(m_targetMemoryMB, m_durationSeconds);
        case PressureMode::SUDDEN:
            return injectSuddenPressure(m_targetMemoryMB);
        case PressureMode::FRAGMENTATION:
            return injectFragmentation(1000, 1024 * 1024); // 1000 x 1MB blocks
        case PressureMode::LEAK:
            return injectMemoryLeak(10, 10); // 10MB/min for 10 min
        case PressureMode::THRASHING:
            // Thrashing is handled in pressure loop
            return injectGradualPressure(m_targetMemoryMB / 2, m_durationSeconds);
        default:
            return injectGradualPressure(m_targetMemoryMB, m_durationSeconds);
    }
}

FaultInjectionResult MemoryPressureInjector::injectGradualPressure(size_t targetMB, size_t durationSec) {
    FaultInjectionResult result;
    auto start = std::chrono::steady_clock::now();
    
    // Create manifest
    m_lastManifest = FaultManifest(
        generateFaultId("MEMORY"),
        FaultType::MEMORY_EXHAUSTION,
        m_severity,
        "MemoryManager",
        "CLEAR_CACHE"
    );
    m_lastManifest.description = "Gradual memory pressure: " + std::to_string(targetMB) + 
                                   "MB over " + std::to_string(durationSec) + " seconds";
    m_lastManifest.parameters["target_mb"] = targetMB;
    m_lastManifest.parameters["duration_sec"] = durationSec;
    m_lastManifest.parameters["mode"] = "gradual";
    
    notifyPreInjection(m_lastManifest);
    
    // Calculate allocation rate
    size_t allocationStepMB = targetMB / (durationSec > 0 ? durationSec : 1);
    if (allocationStepMB == 0) allocationStepMB = 1;
    
    m_pressureActive.store(true);
    
    // Gradual allocation
    size_t allocated = 0;
    while (allocated < targetMB && m_pressureActive.load()) {
        allocateBlock(allocationStepMB);
        allocated += allocationStepMB;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    result.success = true;
    result.faultId = m_lastManifest.faultId;
    
    auto end = std::chrono::steady_clock::now();
    result.injectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    result.telemetry["allocated_mb"] = m_allocatedMemoryMB.load();
    result.telemetry["target_mb"] = targetMB;
    
    notifyPostInjection(m_lastManifest, result);
    
    FaultInjectionRegistry::instance().getStats().totalInjected++;
    FaultInjectionRegistry::instance().getStats().successfulInjections++;
    
    return result;
}

FaultInjectionResult MemoryPressureInjector::injectSuddenPressure(size_t targetMB) {
    FaultInjectionResult result;
    auto start = std::chrono::steady_clock::now();
    
    m_lastManifest = FaultManifest(
        generateFaultId("MEMORY"),
        FaultType::MEMORY_EXHAUSTION,
        FaultSeverity::HIGH,
        "MemoryManager",
        "CLEAR_CACHE"
    );
    m_lastManifest.description = "Sudden memory pressure: " + std::to_string(targetMB) + "MB";
    m_lastManifest.parameters["target_mb"] = targetMB;
    m_lastManifest.parameters["mode"] = "sudden";
    
    notifyPreInjection(m_lastManifest);
    
    try {
        // Allocate in one go
        allocateBlock(targetMB);
        result.success = true;
    } catch (...) {
        result.success = false;
        result.errorMessage = "Failed to allocate requested memory";
    }
    
    result.faultId = m_lastManifest.faultId;
    
    auto end = std::chrono::steady_clock::now();
    result.injectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    result.telemetry["allocated_mb"] = m_allocatedMemoryMB.load();
    
    notifyPostInjection(m_lastManifest, result);
    
    FaultInjectionRegistry::instance().getStats().totalInjected++;
    if (result.success) {
        FaultInjectionRegistry::instance().getStats().successfulInjections++;
    } else {
        FaultInjectionRegistry::instance().getStats().failedInjections++;
    }
    
    return result;
}

FaultInjectionResult MemoryPressureInjector::injectFragmentation(size_t blockCount, size_t blockSize) {
    FaultInjectionResult result;
    auto start = std::chrono::steady_clock::now();
    
    m_lastManifest = FaultManifest(
        generateFaultId("MEMORY"),
        FaultType::MEMORY_EXHAUSTION,
        m_severity,
        "MemoryManager",
        "CLEAR_CACHE"
    );
    m_lastManifest.description = "Memory fragmentation: " + std::to_string(blockCount) + 
                                   " blocks of " + std::to_string(blockSize) + " bytes";
    m_lastManifest.parameters["block_count"] = blockCount;
    m_lastManifest.parameters["block_size"] = blockSize;
    m_lastManifest.parameters["mode"] = "fragmentation";
    
    notifyPreInjection(m_lastManifest);
    
    createFragmentation(blockCount, blockSize);
    
    result.success = true;
    result.faultId = m_lastManifest.faultId;
    
    auto end = std::chrono::steady_clock::now();
    result.injectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    result.telemetry["allocated_mb"] = m_allocatedMemoryMB.load();
    result.telemetry["fragmented_blocks"] = m_fragmentedBlocks.size();
    
    notifyPostInjection(m_lastManifest, result);
    
    FaultInjectionRegistry::instance().getStats().totalInjected++;
    FaultInjectionRegistry::instance().getStats().successfulInjections++;
    
    return result;
}

FaultInjectionResult MemoryPressureInjector::injectMemoryLeak(size_t leakRateMBPerMin, size_t durationMin) {
    FaultInjectionResult result;
    auto start = std::chrono::steady_clock::now();
    
    m_lastManifest = FaultManifest(
        generateFaultId("MEMORY"),
        FaultType::MEMORY_EXHAUSTION,
        m_severity,
        "MemoryManager",
        "CLEAR_CACHE"
    );
    m_lastManifest.description = "Memory leak simulation: " + std::to_string(leakRateMBPerMin) + 
                                   "MB/min for " + std::to_string(durationMin) + " minutes";
    m_lastManifest.parameters["leak_rate_mb_per_min"] = leakRateMBPerMin;
    m_lastManifest.parameters["duration_min"] = durationMin;
    m_lastManifest.parameters["mode"] = "leak";
    
    notifyPreInjection(m_lastManifest);
    
    // Simulate leak by allocating without freeing
    size_t totalLeakMB = 0;
    auto targetLeakMB = leakRateMBPerMin * durationMin;
    
    while (totalLeakMB < targetLeakMB && m_pressureActive.load()) {
        allocateBlock(leakRateMBPerMin);
        totalLeakMB += leakRateMBPerMin;
        std::this_thread::sleep_for(std::chrono::minutes(1));
    }
    
    result.success = true;
    result.faultId = m_lastManifest.faultId;
    
    auto end = std::chrono::steady_clock::now();
    result.injectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    result.telemetry["leaked_mb"] = totalLeakMB;
    result.telemetry["target_leak_mb"] = targetLeakMB;
    
    notifyPostInjection(m_lastManifest, result);
    
    FaultInjectionRegistry::instance().getStats().totalInjected++;
    FaultInjectionRegistry::instance().getStats().successfulInjections++;
    
    return result;
}

void MemoryPressureInjector::allocateBlock(size_t sizeMB) {
    std::lock_guard<std::mutex> lock(m_blocksMutex);
    
    size_t sizeBytes = sizeMB * 1024 * 1024;
    auto block = std::make_unique<char[]>(sizeBytes);
    
    // Touch the memory to ensure it's committed
    for (size_t i = 0; i < sizeBytes; i += 4096) {
        block[i] = static_cast<char>(i % 256);
    }
    
    m_allocatedBlocks.push_back(std::move(block));
    m_allocatedMemoryMB.fetch_add(sizeMB);
}

void MemoryPressureInjector::deallocateBlock(size_t index) {
    std::lock_guard<std::mutex> lock(m_blocksMutex);
    
    if (index < m_allocatedBlocks.size()) {
        // Estimate size (we don't track exact sizes in this simple implementation)
        m_allocatedBlocks.erase(m_allocatedBlocks.begin() + index);
        // Note: actual memory tracking would need exact sizes
    }
}

void MemoryPressureInjector::createFragmentation(size_t blockCount, size_t blockSize) {
    std::lock_guard<std::mutex> lock(m_blocksMutex);
    
    // Allocate all blocks
    for (size_t i = 0; i < blockCount; ++i) {
        auto block = std::make_unique<char[]>(blockSize);
        m_fragmentedBlocks.push_back(std::move(block));
    }
    
    // Free every other block to create fragmentation
    for (size_t i = 0; i < m_fragmentedBlocks.size(); i += 2) {
        m_fragmentedBlocks[i].reset();
    }
    
    m_allocatedMemoryMB.fetch_add((blockCount * blockSize) / (1024 * 1024));
}

void MemoryPressureInjector::releaseAllPressure() {
    m_pressureActive.store(false);
    
    std::lock_guard<std::mutex> lock(m_blocksMutex);
    m_allocatedBlocks.clear();
    m_fragmentedBlocks.clear();
    m_allocatedMemoryMB.store(0);
}

} // namespace Validation
} // namespace RawrXD