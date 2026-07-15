#pragma once

#include "../lora/LoRAAdapterManager.h"
#include <filesystem>

namespace RawrXD::E2E {

/**
 * @brief Validates serialization integrity
 * 
 * Phase 19: Round-trip testing for adapter persistence
 */
class IntegrityEngine {
public:
    /**
     * @brief Validate serialization round-trip
     * @param adapter Adapter to test
     * @return true if round-trip successful
     */
    static bool ValidateSerializationRoundTrip(const LoRAAdapter& adapter);
    
    /**
     * @brief Detect corruption in saved file
     * @param path File to check
     * @return true if corruption detected
     */
    static bool DetectCorruption(const std::filesystem::path& path);
    
    /**
     * @brief Simulate file corruption for testing
     * @param path File to corrupt
     * @return true if corruption applied
     */
    static bool SimulateCorruption(const std::filesystem::path& path);
    
    /**
     * @brief Validate checksum of file
     * @param path File to validate
     * @return true if checksum valid
     */
    static bool ValidateChecksum(const std::filesystem::path& path);
};

} // namespace RawrXD::E2E
