// ============================================================================
// optimizer/sme2_lowering.cpp - SME2 Multi-Vector Outer-Product Lowering
// Coordinates VG2/VG4 tuple allocation, multi-vector loads, and FMOPA
// ============================================================================

#include <cstdint>
#include <vector>
#include <memory>
#include <stdexcept>
#include "sme2_allocator.hpp"

#ifndef SME2_LOWERING_H
#define SME2_LOWERING_H

// SME2 IR Opcodes (matches sme2_lowering.asm dispatch)
enum SME2Opcode : uint16_t {
    SME2_OP_SMSTART     = 0xB0,
    SME2_OP_SMSTOP      = 0xB1,
    SME2_OP_ZERO_VG2    = 0xB2,
    SME2_OP_ZERO_VG4    = 0xB3,
    SME2_OP_LD1W_VG2    = 0xB4,
    SME2_OP_LD1W_VG4    = 0xB5,
    SME2_OP_ST1W_VG2    = 0xB6,
    SME2_OP_ST1W_VG4    = 0xB7,
    SME2_OP_FMOPA_VG2_S = 0xB8,
    SME2_OP_FMOPA_VG4_S = 0xB9,
    SME2_OP_FMOPA_VG2_D = 0xBA,
    SME2_OP_FMOPA_VG4_D = 0xBB,
    SME2_OP_LD1D_VG2    = 0xBC,
    SME2_OP_LD1D_VG4    = 0xBD,
    SME2_OP_ST1D_VG2    = 0xBE,
    SME2_OP_ST1D_VG4    = 0xBF
};

// SME2 IR Node Structure (32 bytes)
struct SME2IRNode {
    uint16_t opcode;      // SME2Opcode
    uint8_t  tile_idx;    // ZAda tile index (0..3) or SMSTART flags
    uint8_t  reserved;
    uint32_t zt_base;     // Zt base register (VG2/VG4 aligned)
    uint32_t zm_base;     // Zm base register (VG2/VG4 aligned)
    uint32_t xn_base;     // Xn base GP register
    uint32_t xm_index;    // Xm index GP register
    uint32_t pn_pred;     // Pn governing predicate (0..7)
    uint32_t pm_pred;     // Pm governing predicate (0..7)
};

class SME2Lowerer {
private:
    SME2RegisterAllocator allocator;

public:
    // Emit a VG2 (2-way) multi-vector GEMM outer product sequence
    std::vector<SME2IRNode> EmitMultiVectorGEMM_VG2(
        uint32_t base_a, uint32_t idx_a,
        uint32_t base_b, uint32_t idx_b,
        uint32_t base_c, uint32_t idx_c,
        uint32_t pn_pred, uint32_t pm_pred)
    {
        std::vector<SME2IRNode> ir_stream;

        VectorTuple tuple_a = allocator.AcquireVectorTuple(TupleType::VG2);
        VectorTuple tuple_b = allocator.AcquireVectorTuple(TupleType::VG2);
        int za_tile = allocator.AcquireZATile32();

        if (za_tile < 0) {
            throw std::runtime_error("SME2: No ZA tiles available.");
        }

        // 1. Enable SME2 Streaming Mode
        ir_stream.push_back({SME2_OP_SMSTART, 3, 0, 0, 0, 0, 0, 0, 0});

        // 2. Clear accumulator tile
        ir_stream.push_back({SME2_OP_ZERO_VG2, (uint8_t)(1 << za_tile), 0, 0, 0, 0, 0, 0, 0});

        // 3. Load VG2 tuples
        ir_stream.push_back({SME2_OP_LD1W_VG2, 0, 0, tuple_a.base_reg, 0, base_a, idx_a, pn_pred, 0});
        ir_stream.push_back({SME2_OP_LD1W_VG2, 0, 0, tuple_b.base_reg, 0, base_b, idx_b, pm_pred, 0});

        // 4. Compute VG2 outer product
        ir_stream.push_back({SME2_OP_FMOPA_VG2_S, (uint8_t)za_tile, 0,
                             tuple_a.base_reg, tuple_b.base_reg,
                             0, 0, pn_pred, pm_pred});

        // 5. Store tile slices
        for (uint32_t slice = 0; slice < 2; ++slice) {
            ir_stream.push_back({SME2_OP_ST1W_VG2, (uint8_t)za_tile, 0,
                                 (uint32_t)slice, 0, base_c, idx_c, pn_pred, 0});
        }

        // 6. Exit Streaming Mode
        ir_stream.push_back({SME2_OP_SMSTOP, 3, 0, 0, 0, 0, 0, 0, 0});

        allocator.ReleaseVectorTuple(tuple_a);
        allocator.ReleaseVectorTuple(tuple_b);
        allocator.ReleaseZATile32(za_tile);

        return ir_stream;
    }

    // Emit a VG4 (4-way) multi-vector GEMM outer product sequence
    std::vector<SME2IRNode> EmitMultiVectorGEMM_VG4(
        uint32_t base_a, uint32_t idx_a,
        uint32_t base_b, uint32_t idx_b,
        uint32_t base_c, uint32_t idx_c,
        uint32_t pn_pred, uint32_t pm_pred)
    {
        std::vector<SME2IRNode> ir_stream;

        VectorTuple tuple_a = allocator.AcquireVectorTuple(TupleType::VG4);
        VectorTuple tuple_b = allocator.AcquireVectorTuple(TupleType::VG4);
        int za_tile = allocator.AcquireZATile32();

        if (za_tile < 0) {
            throw std::runtime_error("SME2: No ZA tiles available.");
        }

        // 1. Enable SME2 Streaming Mode
        ir_stream.push_back({SME2_OP_SMSTART, 3, 0, 0, 0, 0, 0, 0, 0});

        // 2. Clear accumulator tile
        ir_stream.push_back({SME2_OP_ZERO_VG4, (uint8_t)(1 << za_tile), 0, 0, 0, 0, 0, 0, 0});

        // 3. Load VG4 tuples (4 vectors each)
        ir_stream.push_back({SME2_OP_LD1W_VG4, 0, 0, tuple_a.base_reg, 0, base_a, idx_a, pn_pred, 0});
        ir_stream.push_back({SME2_OP_LD1W_VG4, 0, 0, tuple_b.base_reg, 0, base_b, idx_b, pm_pred, 0});

        // 4. Compute VG4 outer product (4x throughput)
        ir_stream.push_back({SME2_OP_FMOPA_VG4_S, (uint8_t)za_tile, 0,
                             tuple_a.base_reg, tuple_b.base_reg,
                             0, 0, pn_pred, pm_pred});

        // 5. Store tile slices
        for (uint32_t slice = 0; slice < 4; ++slice) {
            ir_stream.push_back({SME2_OP_ST1W_VG4, (uint8_t)za_tile, 0,
                                 (uint32_t)slice, 0, base_c, idx_c, pn_pred, 0});
        }

        // 6. Exit Streaming Mode
        ir_stream.push_back({SME2_OP_SMSTOP, 3, 0, 0, 0, 0, 0, 0, 0});

        allocator.ReleaseVectorTuple(tuple_a);
        allocator.ReleaseVectorTuple(tuple_b);
        allocator.ReleaseZATile32(za_tile);

        return ir_stream;
    }

    void Reset() { allocator.Reset(); }
};

#endif // SME2_LOWERING_H
