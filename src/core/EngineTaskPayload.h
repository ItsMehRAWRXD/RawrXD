// ============================================================================
// EngineTaskPayload.h — Unified Cylinder Chamber Payload
// ============================================================================
// Passed via RDX to all 6 cylinder chambers. Contains subsystem pointers
// and scheduling metadata required by Chamber 3 (Sovereign Scheduler).
// ============================================================================

#pragma once
#include <cstdint>
#include <cstddef>
#include "RawrXD_Scheduler.h"

// Forward MASM exports — defined in their respective .asm units
extern "C" {
    void GhostParser_ScanVectorized_AVX512(void* params) noexcept;
    void KV_StreamStore_AVX512(void* params) noexcept;
    void KV_StreamStore_AVX2(void* params) noexcept;
    void Quant_Dequant_INT8_AVX512(void* params) noexcept;
}

namespace RawrXD {

    // Unified operational payload passed across cylinder chambers via RDX
    struct alignas(16) EngineTaskPayload {
        // Subsystem Data Pointers (Chambers 0-2)
        void*   sourceBuffer{ nullptr };
        size_t  bufferLength{ 0 };
        float*  kvApertureAddress{ nullptr };

        // Chamber 3 Scheduler Core Context
        ThreadLeaseContext schedulerCtx{};
        int32_t            targetPriorityLevel{ 15 }; // THREAD_PRIORITY_TIME_CRITICAL
        uint64_t           ccxCoreAffinityMask{ 0x00000000FFFFFFFF }; // First 8 logical threads

        // Chambers 4-5 reserved fields (future expansion)
        void*  reservedCh4{ nullptr };
        void*  reservedCh5{ nullptr };
    };

    static_assert(alignof(EngineTaskPayload) >= 16, "EngineTaskPayload must be 16-byte aligned for AVX-512");

} // namespace RawrXD
