// ============================================================================
// MemoryPressureInjector.hpp — Memory Exhaustion Simulation
// ============================================================================
// Simulates memory pressure and exhaustion scenarios.
// ============================================================================

#pragma once

#include "FaultInjector.hpp"
#include <vector>
#include <memory>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Memory Pressure Injector
// ============================================================================
class MemoryPressureInjector : public FaultInjector {
public:
    MemoryPressureInjector();
    ~MemoryPressureInjector() override;
    
    // FaultInjector interface
    FaultType getType() const override { return FaultType::MEMORY_EXHAUSTION; }
    std::string getName() const override { return "MemoryPressureInjector"; }
    FaultInjectionResult inject() override;
    bool isAvailable() const override { return true; }
    
    bool initialize() override;
    void shutdown() override;
    
    // Pressure modes
    enum class PressureMode {
        GRADUAL,            // Slowly increase memory usage
        SUDDEN,             // Immediate large allocation
        FRAGMENTATION,      // Create fragmented heap
        LEAK,               // Simulate memory leak
        THRASHING           // Rapid alloc/free causing thrashing
    };
    
    void setPressureMode(PressureMode mode) { m_pressureMode = mode; }
    PressureMode getPressureMode() const { return m_pressureMode; }
    
    // Configuration
    void setTargetMemoryMB(size_t mb) { m_targetMemoryMB = mb; }
    void setAllocationRateMBPerSec(size_t rate) { m_allocationRateMB = rate; }
    void setDurationSeconds(size_t seconds) { m_durationSeconds = seconds; }
    
    // Specific injection methods
    FaultInjectionResult injectGradualPressure(size_t targetMB, size_t durationSec);
    FaultInjectionResult injectSuddenPressure(size_t targetMB);
    FaultInjectionResult injectFragmentation(size_t blockCount, size_t blockSize);
    FaultInjectionResult injectMemoryLeak(size_t leakRateMBPerMin, size_t durationMin);
    
    // Release all allocated memory
    void releaseAllPressure();
    
    // Current status
    size_t getAllocatedMemoryMB() const { return m_allocatedMemoryMB.load(); }
    size_t getActiveBlockCount() const { return m_allocatedBlocks.size(); }

private:
    PressureMode m_pressureMode = PressureMode::GRADUAL;
    size_t m_targetMemoryMB = 1024;          // 1GB default
    size_t m_allocationRateMB = 100;       // 100MB/s default
    size_t m_durationSeconds = 60;           // 1 minute default
    
    std::atomic<size_t> m_allocatedMemoryMB{0};
    std::vector<std::unique_ptr<char[]>> m_allocatedBlocks;
    std::vector<std::unique_ptr<char[]>> m_fragmentedBlocks;
    mutable std::mutex m_blocksMutex;
    
    std::atomic<bool> m_pressureActive{false};
    std::thread m_pressureThread;
    
    void allocateBlock(size_t sizeMB);
    void deallocateBlock(size_t index);
    void pressureLoop();
    void createFragmentation(size_t blockCount, size_t blockSize);
};

} // namespace Validation
} // namespace RawrXD