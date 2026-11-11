// ============================================================================
// optimizer/sme2_allocator.cpp - SME2 VG2/VG4 Multi-Vector & ZA Allocator
// Tracks 32 SVE vector registers (Z0..Z31) and 4 ZA tiles (ZA0..ZA3)
// Enforces VG2 (even-aligned) and VG4 (quad-aligned) tuple constraints
// ============================================================================

#include <cstdint>
#include <stdexcept>
#include <array>

#ifndef SME2_ALLOCATOR_H
#define SME2_ALLOCATOR_H

enum class TupleType : uint8_t {
    SINGLE = 1,  // Single vector register
    VG2    = 2,  // 2-way tuple {Zn, Zn+1}, n must be even
    VG4    = 4   // 4-way tuple {Zn..Zn+3}, n must be quad-aligned
};

struct VectorTuple {
    uint32_t  base_reg; // Base register index (Z0, Z2, Z4, etc.)
    TupleType type;
};

class SME2RegisterAllocator {
private:
    uint32_t allocated_z_mask  = 0; // 32-bit bitmask tracking Z0..Z31
    uint8_t  allocated_za_mask = 0; // 4-bit bitmask tracking ZA0.S..ZA3.S

public:
    // Allocate a contiguous, aligned vector register tuple
    VectorTuple AcquireVectorTuple(TupleType type) {
        uint32_t step = static_cast<uint32_t>(type);

        for (uint32_t base = 0; base < 32; base += step) {
            uint32_t mask_needed = ((1U << step) - 1) << base;
            if ((allocated_z_mask & mask_needed) == 0) {
                allocated_z_mask |= mask_needed;
                return VectorTuple{base, type};
            }
        }
        throw std::runtime_error(
            "SME2 Allocator: Out of aligned SVE vector registers.");
    }

    void ReleaseVectorTuple(const VectorTuple& tuple) {
        uint32_t step = static_cast<uint32_t>(tuple.type);
        uint32_t mask_to_free = ((1U << step) - 1) << tuple.base_reg;
        allocated_z_mask &= ~mask_to_free;
    }

    // Allocate a 32-bit ZA accumulator tile (ZA0.S..ZA3.S)
    int AcquireZATile32() {
        for (int i = 0; i < 4; ++i) {
            if (!(allocated_za_mask & (1 << i))) {
                allocated_za_mask |= (1 << i);
                return i;
            }
        }
        return -1; // Out of ZA matrix tile capacity
    }

    void ReleaseZATile32(int tile_idx) {
        if (tile_idx >= 0 && tile_idx < 4) {
            allocated_za_mask &= ~(1 << tile_idx);
        }
    }

    // Allocate a 64-bit ZA accumulator tile (ZA0.D..ZA1.D)
    int AcquireZATile64() {
        for (int i = 0; i < 2; ++i) {
            if (!(allocated_za_mask & (1 << (i + 4)))) {
                allocated_za_mask |= (1 << (i + 4));
                return i;
            }
        }
        return -1;
    }

    void ReleaseZATile64(int tile_idx) {
        if (tile_idx >= 0 && tile_idx < 2) {
            allocated_za_mask &= ~(1 << (tile_idx + 4));
        }
    }

    uint32_t GetAllocatedZMask() const { return allocated_z_mask; }
    uint8_t  GetAllocatedZAMask() const { return allocated_za_mask; }

    void Reset() {
        allocated_z_mask = 0;
        allocated_za_mask = 0;
    }
};

#endif // SME2_ALLOCATOR_H
