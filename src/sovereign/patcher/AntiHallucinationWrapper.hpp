// AntiHallucinationWrapper.hpp
// C++ wrapper for MASM Anti-Hallucination HotPatcher
// Bridges the MASM implementation with C++ PatchRegistry

#ifndef ANTIHALLUCINATIONWRAPPER_HPP
#define ANTIHALLUCINATIONWRAPPER_HPP

#include <cstdint>
#include <windows.h>

namespace Sovereign {

// Error codes from MASM implementation
enum class AHError {
    OK = 0,
    INVALID_ARG = 1,
    EXPECT_MISMATCH = 2,
    PROTECT_FAIL = 3,
    WRITE_FAIL = 4,
    FLUSH_FAIL = 5,
    ROLLBACK_FAIL = 6
};

// Flags from MASM implementation
enum class AHFlags : uint64_t {
    NONE = 0,
    CAPTURE_ORIGINAL = 0x00000001,
    REQUIRE_MATCH = 0x00000002,
    RESTORE_PROTECT = 0x00000004
};

inline AHFlags operator|(AHFlags a, AHFlags b) {
    return static_cast<AHFlags>(static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}

inline bool hasFlag(AHFlags value, AHFlags flag) {
    return (static_cast<uint64_t>(value) & static_cast<uint64_t>(flag)) != 0;
}

/**
 * @struct AHPatchRequest
 * @brief Layout must match MASM PATCHREQ layout exactly
 */
struct AHPatchRequest {
    void* target;           // +00h
    void* expected;         // +08h
    void* replacement;      // +10h
    void* original;         // +18h
    size_t length;          // +20h
    DWORD oldProtect;       // +28h (stored in qword slot)
    uint64_t flags;         // +30h
};

// MASM function declarations - use C calling convention
// These are defined in the MASM object file and linked statically
extern "C" {
    // Returns AHError code
    uint64_t AH_ApplyPatch(AHPatchRequest* request);
    uint64_t AH_RollbackPatch(AHPatchRequest* request);
    
    // Utility functions
    uint64_t AH_GetLastStatus();
    uint64_t AH_GetLastWin32Error();
    
    // Validation
    int AH_CompareBytes(const void* a, const void* b, size_t len);
    void AH_CopyBytes(void* dst, const void* src, size_t len);
    uint64_t AH_Fnv1a64(const void* data, size_t len);
}

/**
 * @class AntiHallucinationGuard
 * @brief High-level C++ interface to MASM anti-hallucination patcher
 * 
 * Usage:
 *   AntiHallucinationGuard guard;
 *   
 *   AHPatchRequest req{};
 *   req.target = (void*)0x140001000;
 *   req.expected = originalBytes;
 *   req.replacement = patchBytes;
 *   req.length = 16;
 *   req.flags = (uint64_t)(AHFlags::REQUIRE_MATCH | AHFlags::RESTORE_PROTECT);
 *   
 *   if (guard.ApplyPatch(req)) {
 *       // Patch applied successfully
 *   } else {
 *       // Validation failed - possible hallucination
 *       auto error = guard.GetLastError();
 *   }
 */
class AntiHallucinationGuard {
public:
    /**
     * @brief Apply a patch with anti-hallucination validation
     * @param request Patch request with validation parameters
     * @return true if patch applied successfully
     */
    bool ApplyPatch(AHPatchRequest& request);
    
    /**
     * @brief Rollback a previously applied patch
     * @param request Original patch request (must have original buffer)
     * @return true if rollback successful
     */
    bool RollbackPatch(AHPatchRequest& request);
    
    /**
     * @brief Get last error code
     * @return AHError code from last operation
     */
    AHError GetLastError() const;
    
    /**
     * @brief Get last Win32 error
     * @return Windows error code from last failed API call
     */
    DWORD GetLastWin32Error() const;
    
    /**
     * @brief Get error message for error code
     * @param error Error code
     * @return Human-readable error message
     */
    static const char* GetErrorMessage(AHError error);
    
    /**
     * @brief Validate bytes match before patching (standalone)
     * @param target Target memory address
     * @param expected Expected bytes
     * @param len Length to compare
     * @return true if bytes match
     */
    static bool ValidateBytes(const void* target, const void* expected, size_t len);
    
    /**
     * @brief Calculate FNV-1a 64-bit hash
     * @param data Data to hash
     * @param len Length of data
     * @return 64-bit hash value
     */
    static uint64_t CalculateHash(const void* data, size_t len);
};

// Implementation
inline bool AntiHallucinationGuard::ApplyPatch(AHPatchRequest& request) {
    uint64_t result = AH_ApplyPatch(&request);
    return result == static_cast<uint64_t>(AHError::OK);
}

inline bool AntiHallucinationGuard::RollbackPatch(AHPatchRequest& request) {
    uint64_t result = AH_RollbackPatch(&request);
    return result == static_cast<uint64_t>(AHError::OK);
}

inline AHError AntiHallucinationGuard::GetLastError() const {
    return static_cast<AHError>(AH_GetLastStatus());
}

inline DWORD AntiHallucinationGuard::GetLastWin32Error() const {
    return static_cast<DWORD>(AH_GetLastWin32Error());
}

inline const char* AntiHallucinationGuard::GetErrorMessage(AHError error) {
    switch (error) {
        case AHError::OK: return "Success";
        case AHError::INVALID_ARG: return "Invalid argument";
        case AHError::EXPECT_MISMATCH: return "Expected bytes mismatch (hallucination detected)";
        case AHError::PROTECT_FAIL: return "Failed to change memory protection";
        case AHError::WRITE_FAIL: return "Failed to write memory";
        case AHError::FLUSH_FAIL: return "Failed to flush instruction cache";
        case AHError::ROLLBACK_FAIL: return "Failed to rollback patch";
        default: return "Unknown error";
    }
}

inline bool AntiHallucinationGuard::ValidateBytes(const void* target, const void* expected, size_t len) {
    return AH_CompareBytes(target, expected, len) != 0;
}

inline uint64_t AntiHallucinationGuard::CalculateHash(const void* data, size_t len) {
    return AH_Fnv1a64(data, len);
}

} // namespace Sovereign

#endif // ANTIHALLUCINATIONWRAPPER_HPP
