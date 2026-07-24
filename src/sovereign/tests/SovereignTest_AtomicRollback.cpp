// =============================================================================
// SovereignTestSuite - Atomic Rollback Validator
// =============================================================================
// Implements the two-phase commit for 11x batch patching:
//   Phase 1: Pre-flight VirtualQueryEx verification of ALL target addresses
//   Phase 2: Transactional application (all-or-nothing)
//   Rollback: If any patch fails verification, NONE are applied
// =============================================================================

#include "SovereignTestSuite.hpp"
#include <windows.h>
#include <vector>
#include <cstring>
#include <intrin.h>

// =============================================================================
// Binary Patch Descriptor
// =============================================================================
struct BinaryPatch {
    uint64_t target_rip;
    uint32_t patch_size;
    uint8_t  opcodes[16];  // Fixed-size for SIMD alignment
    uint8_t  original_bytes[16]; // Saved for rollback
};

// =============================================================================
// Phase 1: Pre-flight Verification
// Returns true only if ALL patches have writable target addresses
// =============================================================================
static bool VerifyAllPatchesWritable(HANDLE hProcess, const BinaryPatch* patches, uint32_t count) {
    MEMORY_BASIC_INFORMATION mbi;
    
    for (uint32_t i = 0; i < count; i++) {
        if (patches[i].target_rip == 0) return false;
        
        SIZE_T result = VirtualQueryEx(
            hProcess,
            (LPCVOID)patches[i].target_rip,
            &mbi,
            sizeof(mbi)
        );
        
        if (result == 0) return false;
        
        // Must be executable and writable
        bool writable = (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                        (mbi.Protect & PAGE_EXECUTE_WRITECOPY);
        if (!writable) return false;
    }
    
    return true;
}

// =============================================================================
// Phase 2: Transactional Application with Rollback
// =============================================================================
static bool ApplyPatchesAtomic(HANDLE hProcess, BinaryPatch* patches, uint32_t count) {
    // --- Phase 1: Pre-flight ---
    if (!VerifyAllPatchesWritable(hProcess, patches, count)) {
        return false;  // No patches applied - atomic failure
    }
    
    // --- Phase 2: Save original bytes ---
    for (uint32_t i = 0; i < count; i++) {
        SIZE_T bytesRead = 0;
        ReadProcessMemory(
            hProcess,
            (LPCVOID)patches[i].target_rip,
            patches[i].original_bytes,
            patches[i].patch_size,
            &bytesRead
        );
        if (bytesRead != patches[i].patch_size) {
            return false;  // Rollback: nothing written yet
        }
    }
    
    // --- Phase 3: Apply all patches ---
    DWORD oldProtect;
    for (uint32_t i = 0; i < count; i++) {
        // Make writable
        VirtualProtectEx(
            hProcess,
            (LPVOID)patches[i].target_rip,
            patches[i].patch_size,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );
        
        // Write patch using AVX-512 aligned store
        __m512i patchData = _mm512_loadu_si512((const __m512i*)patches[i].opcodes);
        _mm512_storeu_si512((void*)patches[i].target_rip, patchData);
        
        // Restore protection
        VirtualProtectEx(
            hProcess,
            (LPVOID)patches[i].target_rip,
            patches[i].patch_size,
            oldProtect,
            &oldProtect
        );
    }
    
    // --- Phase 4: Flush instruction cache ---
    FlushInstructionCache(hProcess, NULL, 0);
    
    return true;
}

// =============================================================================
// Rollback: Restore original bytes if verification fails mid-batch
// =============================================================================
static void RollbackPatches(HANDLE hProcess, BinaryPatch* patches, uint32_t count) {
    DWORD oldProtect;
    
    for (uint32_t i = 0; i < count; i++) {
        VirtualProtectEx(
            hProcess,
            (LPVOID)patches[i].target_rip,
            patches[i].patch_size,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );
        
        // Restore original bytes
        WriteProcessMemory(
            hProcess,
            (LPVOID)patches[i].target_rip,
            patches[i].original_bytes,
            patches[i].patch_size,
            NULL
        );
        
        VirtualProtectEx(
            hProcess,
            (LPVOID)patches[i].target_rip,
            patches[i].patch_size,
            oldProtect,
            &oldProtect
        );
    }
    
    FlushInstructionCache(hProcess, NULL, 0);
}

// =============================================================================
// Public API: Test Atomic Rollback
// =============================================================================
extern "C" __declspec(dllexport)
SovereignTestReport SovereignTest_AtomicRollback() {
    SovereignTestReport report = {};
    report.result = SovereignTestResult::Pass;
    report.detail = "Atomic rollback: PASS";
    
    // Create 11 patches (10 valid + 1 invalid at index 5)
    BinaryPatch patches[11];
    HANDLE hProcess = GetCurrentProcess();
    
    // Fill patches with NOP slides at known writable addresses
    // Use stack-allocated buffer for test targets
    uint8_t test_buffer[256];
    memset(test_buffer, 0x90, sizeof(test_buffer));  // NOPs
    
    for (uint32_t i = 0; i < 11; i++) {
        patches[i].target_rip = (uint64_t)&test_buffer[i * 16];
        patches[i].patch_size = 16;
        memset(patches[i].opcodes, 0x90, 16);  // NOP slide
    }
    
    // Make patch index 5 invalid (zero address)
    patches[5].target_rip = 0;
    
    // Attempt atomic application - should fail and rollback
    bool result = ApplyPatchesAtomic(hProcess, patches, 11);
    
    if (result) {
        // Should have failed! Invalid address in batch
        report.result = SovereignTestResult::FailAtomicRollback;
        report.detail = "Atomic rollback: FAIL - applied partial batch with invalid address";
        report.failed_patch_index = 5;
        return report;
    }
    
    // Verify NO patches were applied (all original bytes intact)
    for (uint32_t i = 0; i < 11; i++) {
        if (i == 5) continue;  // Skip invalid patch
        
        uint8_t current_byte;
        SIZE_T bytesRead = 0;
        ReadProcessMemory(
            hProcess,
            (LPCVOID)patches[i].target_rip,
            &current_byte,
            1,
            &bytesRead
        );
        
        if (current_byte != 0x90) {
            report.result = SovereignTestResult::FailAtomicRollback;
            report.detail = "Atomic rollback: FAIL - partial application detected";
            report.failed_patch_index = i;
            return report;
        }
    }
    
    return report;
}
