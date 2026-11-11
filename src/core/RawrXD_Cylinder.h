// ============================================================================
// RawrXD_Cylinder.h — 6-Shot Execution Cylinder
// ============================================================================
// L1 cache-aligned (64 bytes) lock-free dispatch table with bitmask filtering.
// MASM backend: Cylinder_RotateAndFireMasked from RAWRXD_CYLINDER.asm
// ============================================================================

#pragma once
#include <cstdint>
#include <atomic>

extern "C" {
    // MASM64 export from RAWRXD_CYLINDER.asm
    void Cylinder_RotateAndFireMasked(
        void* cylinder,
        void* payload,
        uint32_t allowedMask) noexcept;
}

namespace RawrXD {

    // Bitmask constants for chamber selection
    enum ChamberBit : uint32_t {
        MASK_GHOST_PARSER = (1u << 0), // 0x01: Text Scanning Vector
        MASK_KV_APERTURE  = (1u << 1), // 0x02: KV Cache Bypass
        MASK_DEQUANT_ENG  = (1u << 2), // 0x04: Quantization Packer
        MASK_REALTIME_LEP = (1u << 3), // 0x08: Priority Escalator
        MASK_MEDUSA_VALID = (1u << 4), // 0x10: Speculative Validator
        MASK_HW_YIELD     = (1u << 5), // 0x20: Hardware Yield Gate
        MASK_ALL_SHOTS    = 0x3Fu       // 0b00111111
    };

    // 64-byte L1 cache line — exactly 6 function pointers + 16 bytes metadata
    struct alignas(64) ExecutionCylinder {
        // 48 bytes: 6 chamber function pointers
        void(*chamber_0)(void* params) noexcept{ nullptr };
        void(*chamber_1)(void* params) noexcept{ nullptr };
        void(*chamber_2)(void* params) noexcept{ nullptr };
        void(*chamber_3)(void* params) noexcept{ nullptr };
        void(*chamber_4)(void* params) noexcept{ nullptr };
        void(*chamber_5)(void* params) noexcept{ nullptr };

        // 16 bytes: mechanical state
        std::atomic<uint32_t> currentChamber{ 0 };
        uint32_t reservedPadding{ 0 };
        uint64_t accumulatedFires{ 0 };
    };

    static_assert(sizeof(ExecutionCylinder) == 64, "ExecutionCylinder must be exactly 64 bytes");

} // namespace RawrXD
