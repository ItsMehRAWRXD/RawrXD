// ============================================================================
// StateCorruptionInjector.cpp — State Corruption Implementation
// ============================================================================

#include "StateCorruptionInjector.hpp"
#include <cstring>
#include <random>

namespace RawrXD {
namespace Validation {

// ============================================================================
// State Corruption Injector Implementation
// ============================================================================
StateCorruptionInjector::StateCorruptionInjector() = default;

StateCorruptionInjector::~StateCorruptionInjector() {
    shutdown();
}

bool StateCorruptionInjector::initialize() {
    m_initialized.store(true);
    return true;
}

void StateCorruptionInjector::shutdown() {
    // Restore any corrupted regions before shutdown
    std::lock_guard<std::mutex> lock(m_regionsMutex);
    for (auto& pair : m_regions) {
        if (pair.second->isCorrupted.load() && !pair.second->originalData.empty()) {
            std::memcpy(pair.second->ptr, pair.second->originalData.data(), 
                       std::min(pair.second->size, pair.second->originalData.size()));
        }
    }
    m_regions.clear();
    m_initialized.store(false);
}

FaultInjectionResult StateCorruptionInjector::inject() {
    return corruptRandomRegion();
}

void StateCorruptionInjector::registerStateRegion(const std::string& name, void* ptr, size_t size) {
    std::lock_guard<std::mutex> lock(m_regionsMutex);
    auto region = std::make_shared<StateRegion>();
    region->name = name;
    region->ptr = ptr;
    region->size = size;
    region->originalData.resize(size);
    std::memcpy(region->originalData.data(), ptr, size);
    m_regions[name] = region;
}

void StateCorruptionInjector::unregisterStateRegion(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_regionsMutex);
    m_regions.erase(name);
}

FaultInjectionResult StateCorruptionInjector::corruptRegion(const std::string& name) {
    FaultInjectionResult result;
    auto start = std::chrono::steady_clock::now();
    
    std::shared_ptr<StateRegion> region;
    {
        std::lock_guard<std::mutex> lock(m_regionsMutex);
        auto it = m_regions.find(name);
        if (it == m_regions.end()) {
            result.success = false;
            result.errorMessage = "State region '" + name + "' not found";
            return result;
        }
        region = it->second;
    }
    
    if (region->isCorrupted.load()) {
        result.success = false;
        result.errorMessage = "State region '" + name + "' is already corrupted";
        return result;
    }
    
    // Create manifest
    m_lastManifest = FaultManifest(
        generateFaultId("STATE"),
        FaultType::STATE_CORRUPTION,
        m_severity,
        "StateRegion_" + name,
        "ROLLBACK_STATE"
    );
    
    std::string modeStr;
    switch (m_corruptionMode) {
        case CorruptionMode::BIT_FLIP: modeStr = "bit_flip"; break;
        case CorruptionMode::BYTE_OVERWRITE: modeStr = "byte_overwrite"; break;
        case CorruptionMode::NULL_POINTER: modeStr = "null_pointer"; break;
        case CorruptionMode::INVALID_MAGIC: modeStr = "invalid_magic"; break;
        case CorruptionMode::CHECKSUM_FAIL: modeStr = "checksum_fail"; break;
        case CorruptionMode::STRUCT_PADDING: modeStr = "struct_padding"; break;
        case CorruptionMode::STACK_SMASH: modeStr = "stack_smash"; break;
        case CorruptionMode::HEAP_CORRUPTION: modeStr = "heap_corruption"; break;
    }
    
    m_lastManifest.description = "State corruption: " + name + " via " + modeStr;
    m_lastManifest.parameters["region_name"] = name;
    m_lastManifest.parameters["region_size"] = region->size;
    m_lastManifest.parameters["corruption_mode"] = modeStr;
    
    notifyPreInjection(m_lastManifest);
    
    // Execute corruption
    executeCorruption(region);
    
    result.success = true;
    result.faultId = m_lastManifest.faultId;
    
    auto end = std::chrono::steady_clock::now();
    result.injectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    result.telemetry["region_name"] = name;
    result.telemetry["region_size"] = region->size;
    result.telemetry["corruption_mode"] = modeStr;
    
    notifyPostInjection(m_lastManifest, result);
    
    FaultInjectionRegistry::instance().getStats().totalInjected++;
    FaultInjectionRegistry::instance().getStats().successfulInjections++;
    
    return result;
}

FaultInjectionResult StateCorruptionInjector::corruptRandomRegion() {
    auto name = selectRandomRegion();
    if (name.empty()) {
        FaultInjectionResult result;
        result.success = false;
        result.errorMessage = "No state regions available for corruption";
        return result;
    }
    return corruptRegion(name);
}

FaultInjectionResult StateCorruptionInjector::corruptSpecificOffset(const std::string& name, 
                                                                      size_t offset, uint8_t value) {
    FaultInjectionResult result;
    auto start = std::chrono::steady_clock::now();
    
    std::shared_ptr<StateRegion> region;
    {
        std::lock_guard<std::mutex> lock(m_regionsMutex);
        auto it = m_regions.find(name);
        if (it == m_regions.end()) {
            result.success = false;
            result.errorMessage = "State region '" + name + "' not found";
            return result;
        }
        region = it->second;
    }
    
    if (offset >= region->size) {
        result.success = false;
        result.errorMessage = "Offset exceeds region size";
        return result;
    }
    
    // Create manifest
    m_lastManifest = FaultManifest(
        generateFaultId("STATE"),
        FaultType::STATE_CORRUPTION,
        m_severity,
        "StateRegion_" + name,
        "ROLLBACK_STATE"
    );
    m_lastManifest.description = "State corruption: " + name + " at offset " + 
                                   std::to_string(offset) + " with value " + std::to_string(value);
    m_lastManifest.parameters["region_name"] = name;
    m_lastManifest.parameters["offset"] = offset;
    m_lastManifest.parameters["value"] = value;
    m_lastManifest.parameters["corruption_mode"] = "specific_offset";
    
    notifyPreInjection(m_lastManifest);
    
    // Save original if not already saved
    if (region->originalData.empty()) {
        region->originalData.resize(region->size);
        std::memcpy(region->originalData.data(), region->ptr, region->size);
    }
    
    // Apply corruption
    uint8_t* ptr = static_cast<uint8_t*>(region->ptr);
    ptr[offset] = value;
    region->isCorrupted.store(true);
    region->corruptionTime = std::chrono::steady_clock::now();
    
    result.success = true;
    result.faultId = m_lastManifest.faultId;
    
    auto end = std::chrono::steady_clock::now();
    result.injectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    notifyPostInjection(m_lastManifest, result);
    
    FaultInjectionRegistry::instance().getStats().totalInjected++;
    FaultInjectionRegistry::instance().getStats().successfulInjections++;
    
    return result;
}

void StateCorruptionInjector::executeCorruption(const std::shared_ptr<StateRegion>& region) {
    // Save original data
    if (region->originalData.empty()) {
        region->originalData.resize(region->size);
        std::memcpy(region->originalData.data(), region->ptr, region->size);
    }
    
    switch (m_corruptionMode) {
        case CorruptionMode::BIT_FLIP:
            executeBitFlip(region);
            break;
        case CorruptionMode::BYTE_OVERWRITE:
            executeByteOverwrite(region);
            break;
        case CorruptionMode::NULL_POINTER:
            executeNullPointer(region);
            break;
        case CorruptionMode::INVALID_MAGIC:
            executeInvalidMagic(region);
            break;
        case CorruptionMode::CHECKSUM_FAIL:
            executeChecksumFail(region);
            break;
        default:
            executeBitFlip(region);
            break;
    }
    
    region->isCorrupted.store(true);
    region->corruptionTime = std::chrono::steady_clock::now();
}

void StateCorruptionInjector::executeBitFlip(const std::shared_ptr<StateRegion>& region) {
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> offsetDis(0, region->size - 1);
    std::uniform_int_distribution<int> bitDis(0, 7);
    
    size_t offset = offsetDis(gen);
    int bit = bitDis(gen);
    
    uint8_t* ptr = static_cast<uint8_t*>(region->ptr);
    ptr[offset] ^= (1 << bit);
}

void StateCorruptionInjector::executeByteOverwrite(const std::shared_ptr<StateRegion>& region) {
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> offsetDis(0, region->size - 1);
    std::uniform_int_distribution<int> valueDis(0, 255);
    
    // Overwrite 10% of the region with random bytes
    size_t bytesToCorrupt = region->size / 10;
    if (bytesToCorrupt == 0) bytesToCorrupt = 1;
    
    uint8_t* ptr = static_cast<uint8_t*>(region->ptr);
    for (size_t i = 0; i < bytesToCorrupt; ++i) {
        size_t offset = offsetDis(gen);
        ptr[offset] = static_cast<uint8_t>(valueDis(gen));
    }
}

void StateCorruptionInjector::executeNullPointer(const std::shared_ptr<StateRegion>& region) {
    // Set first sizeof(void*) bytes to null
    size_t ptrSize = sizeof(void*);
    if (region->size >= ptrSize) {
        std::memset(region->ptr, 0, ptrSize);
    }
}

void StateCorruptionInjector::executeInvalidMagic(const std::shared_ptr<StateRegion>& region) {
    // Corrupt first 4 bytes (typical magic number size)
    if (region->size >= 4) {
        uint8_t* ptr = static_cast<uint8_t*>(region->ptr);
        ptr[0] = 0xDE;
        ptr[1] = 0xAD;
        ptr[2] = 0xBE;
        ptr[3] = 0xEF;
    }
}

void StateCorruptionInjector::executeChecksumFail(const std::shared_ptr<StateRegion>& region) {
    // Corrupt last byte to invalidate checksum
    if (region->size > 0) {
        uint8_t* ptr = static_cast<uint8_t*>(region->ptr);
        ptr[region->size - 1] ^= 0xFF;
    }
}

std::string StateCorruptionInjector::selectRandomRegion() {
    std::lock_guard<std::mutex> lock(m_regionsMutex);
    
    std::vector<std::string> available;
    for (const auto& pair : m_regions) {
        if (!pair.second->isCorrupted.load()) {
            available.push_back(pair.first);
        }
    }
    
    if (available.empty()) {
        return "";
    }
    
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0, available.size() - 1);
    
    return available[dis(gen)];
}

bool StateCorruptionInjector::verifyStateIntegrity(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_regionsMutex);
    auto it = m_regions.find(name);
    if (it == m_regions.end()) {
        return false;
    }
    
    const auto& region = it->second;
    if (region->originalData.empty()) {
        return true; // No corruption applied
    }
    
    return std::memcmp(region->ptr, region->originalData.data(), region->size) == 0;
}

std::vector<std::string> StateCorruptionInjector::getCorruptedRegions() const {
    std::lock_guard<std::mutex> lock(m_regionsMutex);
    std::vector<std::string> corrupted;
    for (const auto& pair : m_regions) {
        if (pair.second->isCorrupted.load()) {
            corrupted.push_back(pair.first);
        }
    }
    return corrupted;
}

} // namespace Validation
} // namespace RawrXD