// ============================================================================
// StateCorruptionInjector.hpp — Internal State Corruption Simulation
// ============================================================================
// Simulates state corruption to validate rollback recovery strategies.
// ============================================================================

#pragma once

#include "FaultInjector.hpp"
#include <map>
#include <mutex>

namespace RawrXD {
namespace Validation {

// ============================================================================
// State Corruption Injector
// ============================================================================
class StateCorruptionInjector : public FaultInjector {
public:
    StateCorruptionInjector();
    ~StateCorruptionInjector() override;
    
    // FaultInjector interface
    FaultType getType() const override { return FaultType::STATE_CORRUPTION; }
    std::string getName() const override { return "StateCorruptionInjector"; }
    FaultInjectionResult inject() override;
    bool isAvailable() const override { return true; }
    
    bool initialize() override;
    void shutdown() override;
    
    // Corruption modes
    enum class CorruptionMode {
        BIT_FLIP,           // Single bit flip
        BYTE_OVERWRITE,     // Overwrite bytes with garbage
        NULL_POINTER,       // Set pointer to null
        INVALID_MAGIC,      // Corrupt magic number/header
        CHECKSUM_FAIL,      // Invalidate checksum
        STRUCT_PADDING,     // Corrupt struct padding
        STACK_SMASH,        // Stack buffer overflow simulation
        HEAP_CORRUPTION     // Heap metadata corruption
    };
    
    void setCorruptionMode(CorruptionMode mode) { m_corruptionMode = mode; }
    CorruptionMode getCorruptionMode() const { return m_corruptionMode; }
    
    // State registration
    void registerStateRegion(const std::string& name, void* ptr, size_t size);
    void unregisterStateRegion(const std::string& name);
    
    // Specific injection methods
    FaultInjectionResult corruptRegion(const std::string& name);
    FaultInjectionResult corruptRandomRegion();
    FaultInjectionResult corruptSpecificOffset(const std::string& name, size_t offset, uint8_t value);
    
    // State verification
    bool verifyStateIntegrity(const std::string& name) const;
    std::vector<std::string> getCorruptedRegions() const;

private:
    struct StateRegion {
        std::string name;
        void* ptr;
        size_t size;
        std::vector<uint8_t> originalData;
        std::atomic<bool> isCorrupted{false};
        std::chrono::steady_clock::time_point corruptionTime;
    };
    
    std::map<std::string, std::shared_ptr<StateRegion>> m_regions;
    mutable std::mutex m_regionsMutex;
    CorruptionMode m_corruptionMode = CorruptionMode::BIT_FLIP;
    std::atomic<bool> m_initialized{false};
    
    void executeCorruption(const std::shared_ptr<StateRegion>& region);
    void executeBitFlip(const std::shared_ptr<StateRegion>& region);
    void executeByteOverwrite(const std::shared_ptr<StateRegion>& region);
    void executeNullPointer(const std::shared_ptr<StateRegion>& region);
    void executeInvalidMagic(const std::shared_ptr<StateRegion>& region);
    void executeChecksumFail(const std::shared_ptr<StateRegion>& region);
    
    std::string selectRandomRegion();
};

} // namespace Validation
} // namespace RawrXD