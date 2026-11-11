// IPatcher.hpp
// Abstract interface for patcher implementations
// Part of the Sovereign PatchRegistry abstraction layer

#ifndef IPATCHER_HPP
#define IPATCHER_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace Sovereign {

/**
 * @struct PatchRequest
 * @brief Describes a single patch operation
 */
struct PatchRequest {
    std::string module;           // Target module name
    uint64_t address;           // Virtual address to patch
    std::vector<uint8_t> expected;    // Expected original bytes
    std::vector<uint8_t> replacement; // New bytes to write
    std::string reason;         // Human-readable patch rationale
};

/**
 * @struct PatchResult
 * @brief Result of a patch operation
 */
struct PatchResult {
    bool success;               // Operation succeeded
    uint64_t address;           // Address that was patched
    std::string message;        // Status or error message
};

/**
 * @class IPatcher
 * @brief Abstract interface for patcher implementations
 * 
 * Implementations:
 *   - MockPatcher: CI/CD deterministic testing
 *   - HotPatcher: Production live binary patching
 *   - CDBPatcher: Debugger-assisted patching via SovereignCDB
 */
class IPatcher {
public:
    virtual ~IPatcher() = default;

    /**
     * @brief Apply a patch to the target process
     * @param request Patch specification
     * @return Result of the operation
     */
    virtual PatchResult Apply(const PatchRequest& request) = 0;

    /**
     * @brief Rollback a previously applied patch
     * @param request Patch specification (must match original)
     * @return Result of the operation
     */
    virtual PatchResult Rollback(const PatchRequest& request) = 0;

    /**
     * @brief Get the patcher name for registry lookup
     * @return Unique identifier (e.g., "mock", "hot", "cdb")
     */
    virtual const char* Name() const = 0;
};

} // namespace Sovereign

#endif // IPATCHER_HPP
