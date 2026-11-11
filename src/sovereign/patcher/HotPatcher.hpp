// HotPatcher.hpp
// Production live binary patching implementation
// Part of the Sovereign PatchRegistry abstraction layer

#ifndef HOTPATCHER_HPP
#define HOTPATCHER_HPP

#include "IPatcher.hpp"
#include <windows.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>

namespace Sovereign {

/**
 * @struct PatchTransaction
 * @brief Tracks an applied patch for potential rollback
 */
struct PatchTransaction {
    uintptr_t address;              // Target address
    std::vector<uint8_t> original;  // Original bytes (for rollback)
    std::vector<uint8_t> replacement; // Applied bytes
    DWORD oldProtection;            // Original memory protection
    bool committed = false;         // Successfully applied
    uint64_t timestamp = 0;         // Application timestamp
};

/**
 * @class HotPatcher
 * @brief Production live binary patching via Windows APIs
 * 
 * This implementation performs actual in-process memory mutation:
 *   - VirtualProtectEx: Changes page protection to writable/executable
 *   - WriteProcessMemory: Atomically writes patch bytes
 *   - FlushInstructionCache: Ensures CPU sees new instructions
 *   - Transaction tracking: Supports rollback to original state
 * 
 * Usage:
 *   PatchRegistry registry;
 *   registry.Register(std::make_shared<HotPatcher>(GetCurrentProcess()));
 *   auto result = registry.Apply("hot", request);
 */
class HotPatcher : public IPatcher {
    HANDLE process;  // Target process handle
    mutable std::mutex transactionLock;
    std::unordered_map<uintptr_t, PatchTransaction> transactions;  // Applied patches

public:
    /**
     * @brief Construct HotPatcher for a target process
     * @param target Process handle (use GetCurrentProcess() for self-patching)
     */
    explicit HotPatcher(HANDLE target) : process(target) {}

    /**
     * @brief Apply a patch to live process memory
     * @param request Patch specification with address, expected, and replacement bytes
     * @return Result indicating success/failure and message
     */
    PatchResult Apply(const PatchRequest& request) override;

    /**
     * @brief Rollback a previously applied patch
     * @param request Original patch specification (address must match)
     * @return Result indicating success/failure
     */
    PatchResult Rollback(const PatchRequest& request) override;

    /**
     * @brief Get patcher name for registry
     * @return "hot"
     */
    const char* Name() const override { return "hot"; }

    /**
     * @brief Check if a patch exists at the given address
     * @param address Target address
     * @return true if patch was previously applied
     */
    bool HasPatchAt(uintptr_t address) const;

    /**
     * @brief Get transaction info for an address
     * @param address Target address
     * @return Pointer to transaction, or nullptr if not found
     */
    const PatchTransaction* GetTransaction(uintptr_t address) const;

    /**
     * @brief Rollback all applied patches (emergency restore)
     * @return Number of patches rolled back
     */
    size_t RollbackAll();

    /**
     * @brief Get count of active patches
     * @return Number of committed transactions
     */
    size_t GetActivePatchCount() const;

private:
    /**
     * @brief Validate that memory contains expected bytes
     * @param address Target address
     * @param expected Expected byte sequence
     * @return true if memory matches expected
     */
    bool ValidateBytes(uintptr_t address, const std::vector<uint8_t>& expected);

    /**
     * @brief Read bytes from process memory
     * @param address Source address
     * @param size Number of bytes to read
     * @param outBuffer Output buffer (must be pre-allocated)
     * @return true if read succeeded
     */
    bool ReadBytes(uintptr_t address, size_t size, uint8_t* outBuffer);

    /**
     * @brief Write bytes to process memory with protection escalation
     * @param address Target address
     * @param bytes Bytes to write
     * @param oldProtection Output: original protection flags
     * @return true if write succeeded
     */
    bool WriteBytes(uintptr_t address, const std::vector<uint8_t>& bytes, DWORD& oldProtection);

    /**
     * @brief Restore original memory protection
     * @param address Target address
     * @param size Region size
     * @param protection Original protection flags
     * @return true if restoration succeeded
     */
    bool RestoreProtection(uintptr_t address, size_t size, DWORD protection);

    /**
     * @brief Invalidate instruction cache after patch
     * @param address Target address
     * @param size Region size
     */
    void InvalidateCache(uintptr_t address, size_t size);
};

} // namespace Sovereign

#endif // HOTPATCHER_HPP
