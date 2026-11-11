// AntiHallucinationHotPatcher.hpp
// C++ wrapper for MASM anti-hallucination hot patcher
// Provides type-safe interface to assembly validation routines

#ifndef ANTIHALLUCINATIONHOTPATCHER_HPP
#define ANTIHALLUCINATIONHOTPATCHER_HPP

#include <cstdint>
#include <string>
#include <vector>

// Link against the MASM object file
extern "C" {
    // Returns AH_OK (0) or error code
    uint64_t AH_ApplyPatch(void* request);
    uint64_t AH_RollbackPatch(void* request);
    uint64_t AH_GetLastStatus(void);
    uint64_t AH_GetLastWin32Error(void);
    uint64_t AH_Fnv1a64(const void* data, uint64_t len);
    
    // Byte operations
    uint32_t AH_CompareBytes(const void* a, const void* b, uint64_t len);
    void AH_CopyBytes(void* dst, const void* src, uint64_t len);
}

namespace Sovereign {

// Error codes from MASM
enum class AHError : uint64_t {
    OK = 0,
    INVALID_ARG = 1,
    EXPECT_MISMATCH = 2,
    PROTECT_FAIL = 3,
    WRITE_FAIL = 4,
    FLUSH_FAIL = 5,
    ROLLBACK_FAIL = 6
};

// Patch flags
enum class AHFlags : uint64_t {
    NONE = 0,
    CAPTURE_ORIGINAL = 0x00000001,
    REQUIRE_MATCH = 0x00000002,
    RESTORE_PROTECT = 0x00000004
};

inline AHFlags operator|(AHFlags a, AHFlags b) {
    return static_cast<AHFlags>(
        static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}

inline bool HasFlag(AHFlags flags, AHFlags test) {
    return (static_cast<uint64_t>(flags) & static_cast<uint64_t>(test)) != 0;
}

/**
 * @struct AHPatchRequest
 * @brief Layout must match MASM PATCHREQ structure exactly
 * 
 * Memory layout (64-bit):
 * +00h  target ptr
 * +08h  expected ptr  
 * +10h  replacement ptr
 * +18h  original ptr
 * +20h  length qword
 * +28h  oldProtect dword (in qword slot)
 * +30h  flags qword
 */
#pragma pack(push, 8)
struct AHPatchRequest {
    void* target = nullptr;
    const void* expected = nullptr;
    const void* replacement = nullptr;
    void* original = nullptr;
    uint64_t length = 0;
    uint64_t oldProtect = 0;  // Actually DWORD, but padded to QWORD
    uint64_t flags = 0;
};
#pragma pack(pop)

/**
 * @class AntiHallucinationHotPatcher
 * @brief High-level C++ wrapper for MASM validation patcher
 * 
 * Provides:
 * - Byte-level validation before patching
 * - Automatic rollback on failure
 * - Instruction cache flushing
 * - Memory protection management
 * - Anti-hallucination guards
 */
class AntiHallucinationHotPatcher {
public:
    /**
     * @brief Apply a patch with full validation
     * @param target Address to patch
     * @param expected Expected bytes at target (for validation)
     * @param replacement New bytes to write
     * @param flags Patch options
     * @return true if patch applied successfully
     */
    static bool ApplyPatch(void* target,
                          const std::vector<uint8_t>& expected,
                          const std::vector<uint8_t>& replacement,
                          AHFlags flags = AHFlags::REQUIRE_MATCH | AHFlags::RESTORE_PROTECT);
    
    /**
     * @brief Apply patch with automatic rollback buffer
     * @param target Address to patch
     * @param expected Expected bytes
     * @param replacement New bytes
     * @param originalBuffer Buffer to store original bytes (must be pre-allocated)
     * @return true if successful
     */
    static bool ApplyPatchWithCapture(void* target,
                                     const std::vector<uint8_t>& expected,
                                     const std::vector<uint8_t>& replacement,
                                     std::vector<uint8_t>& originalBuffer);
    
    /**
     * @brief Rollback a previously applied patch
     * @param target Original target address
     * @param original Original bytes to restore
     * @return true if rollback successful
     */
    static bool RollbackPatch(void* target, const std::vector<uint8_t>& original);
    
    /**
     * @brief Get last error code
     * @return Error code from last operation
     */
    static AHError GetLastError();
    
    /**
     * @brief Get last Win32 error
     * @return Windows error code
     */
    static uint64_t GetLastWin32Error();
    
    /**
     * @brief Get human-readable error message
     * @param error Error code
     * @return Error description
     */
    static const char* GetErrorString(AHError error);
    
    /**
     * @brief Calculate FNV-1a 64-bit hash
     * @param data Data to hash
     * @param len Length in bytes
     * @return 64-bit hash value
     */
    static uint64_t HashBytes(const void* data, uint64_t len);
    
    /**
     * @brief Validate that memory matches expected bytes
     * @param target Memory address
     * @param expected Expected bytes
     * @return true if matches
     */
    static bool ValidateBytes(const void* target, const std::vector<uint8_t>& expected);
    
    /**
     * @brief Copy bytes safely
     * @param dst Destination
     * @param src Source
     * @param len Length
     */
    static void CopyBytes(void* dst, const void* src, uint64_t len);
};

} // namespace Sovereign

#endif // ANTIHALLUCINATIONHOTPATCHER_HPP
