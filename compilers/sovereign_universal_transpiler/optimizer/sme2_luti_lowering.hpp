// ============================================================================
// optimizer/sme2_luti_lowering.hpp - SME2 LUTI Dequantization Lowering Engine
// Manages ZT0 table loading, LUTI2/LUTI4 expansion, and FMOPA accumulation
// ============================================================================

#include <cstdint>
#include <vector>
#include <stdexcept>

#ifndef SME2_LUTI_LOWERING_H
#define SME2_LUTI_LOWERING_H

// LUTI IR Opcodes (matches sme2_luti_bridge.asm dispatch)
enum SME2LUTIOpcode : uint16_t {
    OP_SME2_SMSTART      = 0xBF,
    OP_SME2_SMSTOP       = 0xBE,
    OP_SME2_LDR_ZT0      = 0xC0,
    OP_SME2_LUTI2_VG2_S  = 0xC1,
    OP_SME2_LUTI2_VG4_S  = 0xC2,
    OP_SME2_LUTI4_VG2_S  = 0xC3,
    OP_SME2_LUTI4_VG4_S  = 0xC4,
    OP_SME2_LUTI2_VG2_H  = 0xC5,
    OP_SME2_LUTI2_VG4_H  = 0xC6,
    OP_SME2_LUTI4_VG2_H  = 0xC7,
    OP_SME2_LUTI4_VG4_H  = 0xC8,
    OP_SME2_LUTI2_VG2_B  = 0xC9,
    OP_SME2_LUTI2_VG4_B  = 0xCA,
    OP_SME2_LUTI4_VG2_B  = 0xCB,
    OP_SME2_LUTI4_VG4_B  = 0xCC,
    OP_SME2_LUTI2_VG2_D  = 0xCD,
    OP_SME2_LUTI2_VG4_D  = 0xCE,
    OP_SME2_LUTI4_VG2_D  = 0xCF,
    OP_SME2_LUTI4_VG4_D  = 0xD0,
    OP_SME2_LD1B_INDEX   = 0xD1,
    OP_SME2_FMOPA_VG4    = 0xD2
};

struct LUTIInstructionNode {
    SME2LUTIOpcode op;
    uint32_t       dest_reg;   // Destination Tuple Base (Zd) or Tile (ZAda)
    uint32_t       src_reg;    // Source Index Register (Zn)
    uint32_t       base_gp;    // Memory Base GP (Xn)
    uint32_t       index_gp;   // Memory Index GP (Xm)
    uint32_t       lut_imm;    // Table index sub-offset imm
    uint32_t       pred_reg;   // Predicate
};

class SME2LUTIDequantizer {
public:
    // Build an INT4 dequantizing matrix multiply kernel using LUTI4 + FMOPA (VG4)
    static std::vector<LUTIInstructionNode> LowerINT4QuantizedGEMM(
        uint32_t table_ptr_gp,    // Pointer to 512-bit ZT0 scale table
        uint32_t packed_idx_gp,   // Pointer to INT4 packed index stream
        uint32_t activation_gp,   // Pointer to FP32 dense activations
        uint32_t out_matrix_gp,   // Pointer to Output matrix C
        uint32_t pred_mask)
    {
        std::vector<LUTIInstructionNode> node_stream;

        // 1. Enter Streaming Mode
        node_stream.push_back({OP_SME2_SMSTART, 3, 0, 0, 0, 0, 0});

        // 2. Load 512-bit Dequantization Scale Table into ZT0
        node_stream.push_back({OP_SME2_LDR_ZT0, 0, 0, table_ptr_gp, 0, 0, 0});

        // 3. Load packed 4-bit index bytes into Z0
        node_stream.push_back({OP_SME2_LD1B_INDEX, 0, 0, packed_idx_gp, 0, 0, pred_mask});

        // 4. Dequantize INT4 indices via LUTI4 into 4-way FP32 tuple Z4..Z7 (VG4)
        node_stream.push_back({
            OP_SME2_LUTI4_VG4_S,
            4,  /* Dest Zd = Z4 (allocates Z4..Z7) */
            0,  /* Source Zn = Z0 */
            0, 0,
            0,  /* Sub-index offset 0 */
            pred_mask
        });

        // 5. Load FP32 activation vector tuple Z8..Z11 (VG4)
        node_stream.push_back({OP_SME2_LD1B_INDEX, 8, 0, activation_gp, 0, 0, pred_mask});

        // 6. Execute SME2 Multi-Vector Outer Product
        node_stream.push_back({
            OP_SME2_FMOPA_VG4,
            0,  /* ZA0 tile */
            4,  /* Weight tuple Z4..Z7 */
            8,  /* Activation tuple Z8..Z11 */
            0, 0,
            pred_mask
        });

        // 7. Exit Streaming Mode
        node_stream.push_back({OP_SME2_SMSTOP, 3, 0, 0, 0, 0, 0});

        return node_stream;
    }

    // Build an INT2 dequantizing kernel using LUTI2 + FMOPA (VG4)
    static std::vector<LUTIInstructionNode> LowerINT2QuantizedGEMM(
        uint32_t table_ptr_gp,
        uint32_t packed_idx_gp,
        uint32_t activation_gp,
        uint32_t out_matrix_gp,
        uint32_t pred_mask)
    {
        std::vector<LUTIInstructionNode> node_stream;

        node_stream.push_back({OP_SME2_SMSTART, 3, 0, 0, 0, 0, 0});
        node_stream.push_back({OP_SME2_LDR_ZT0, 0, 0, table_ptr_gp, 0, 0, 0});
        node_stream.push_back({OP_SME2_LD1B_INDEX, 0, 0, packed_idx_gp, 0, 0, pred_mask});

        // LUTI2 expands 2-bit indices -> 4 FP32 vectors per byte
        node_stream.push_back({
            OP_SME2_LUTI2_VG4_S,
            4, 0, 0, 0, 0, pred_mask
        });

        node_stream.push_back({OP_SME2_LD1B_INDEX, 8, 0, activation_gp, 0, 0, pred_mask});
        node_stream.push_back({OP_SME2_FMOPA_VG4, 0, 4, 8, 0, 0, pred_mask});
        node_stream.push_back({OP_SME2_SMSTOP, 3, 0, 0, 0, 0, 0});

        return node_stream;
    }
};

#endif // SME2_LUTI_LOWERING_H
