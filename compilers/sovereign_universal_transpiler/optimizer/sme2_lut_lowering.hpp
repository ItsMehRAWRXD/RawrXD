// ============================================================================
// optimizer/sme2_lut_lowering.cpp - SME2 LUTI Dequantization Lowering
// Manages quantized weight dequantization via LUTI2/LUTI4 hardware lookups
// ============================================================================

#include <cstdint>
#include <vector>
#include <stdexcept>
#include "sme2_allocator.hpp"

#ifndef SME2_LUT_LOWERING_H
#define SME2_LUT_LOWERING_H

// LUT IR Opcodes (matches sme2_lut_lowering.asm dispatch)
enum LUTOpcode : uint16_t {
    LUT_OP_LUTI2_S     = 0xC0,  // FP32 2-bit lookup
    LUT_OP_LUTI4_S     = 0xC1,  // FP32 4-bit lookup
    LUT_OP_LUTI4_VG2_S = 0xC2,  // FP32 4-bit VG2 lookup
    LUT_OP_LUTI2_H     = 0xC3,  // FP16 2-bit lookup
    LUT_OP_LUTI4_H     = 0xC4,  // FP16 4-bit lookup
    LUT_OP_LUTI2_B     = 0xC5,  // INT8 2-bit lookup
    LUT_OP_LUTI4_B     = 0xC6,  // INT8 4-bit lookup
    LUT_OP_LUTI2_D     = 0xC7,  // FP64 2-bit lookup
    LUT_OP_LUTI4_D     = 0xC8   // FP64 4-bit lookup
};

enum class QuantMode : uint8_t {
    INT2_LUTI2,  // 2-bit quantization (4 centroid levels)
    INT4_LUTI4   // 4-bit quantization (16 centroid levels)
};

struct LUTIRNode {
    uint16_t opcode;      // LUTOpcode
    uint8_t  reserved;
    uint8_t  segment;     // Segment index (0..3)
    uint32_t zd_reg;      // Destination vector / base
    uint32_t zn_table;    // Table centroid vector base
    uint32_t zm_index;    // Packed quantized weight index vector
    uint32_t padding;
};

class SME2DequantizationLowerer {
private:
    SME2RegisterAllocator allocator;

public:
    // Lower quantized weight expansion into LUTI instructions
    std::vector<LUTIRNode> LowerWeightDequantization(
        QuantMode mode,
        uint32_t zm_packed_weights,
        const std::vector<float>& fp32_centroids)
    {
        std::vector<LUTIRNode> nodes;

        if (mode == QuantMode::INT2_LUTI2) {
            if (fp32_centroids.size() != 4) {
                throw std::invalid_argument(
                    "INT2_LUTI2 requires exactly 4 FP32 centroid values.");
            }

            // Allocate 1 table vector for 4 FP32 centroids
            VectorTuple zn_table = allocator.AcquireVectorTuple(TupleType::SINGLE);
            VectorTuple zd_dest  = allocator.AcquireVectorTuple(TupleType::SINGLE);

            // Dequantize 4 segments of 2-bit packed indices
            for (uint32_t segment = 0; segment < 4; ++segment) {
                nodes.push_back({
                    LUT_OP_LUTI2_S, 0, (uint8_t)segment,
                    zd_dest.base_reg,
                    zn_table.base_reg,
                    zm_packed_weights, 0
                });
            }

            allocator.ReleaseVectorTuple(zd_dest);
            allocator.ReleaseVectorTuple(zn_table);

        } else if (mode == QuantMode::INT4_LUTI4) {
            if (fp32_centroids.size() != 16) {
                throw std::invalid_argument(
                    "INT4_LUTI4 requires exactly 16 FP32 centroid values.");
            }

            // Allocate VG2 tuple for 16 FP32 centroids
            VectorTuple zn_table_tuple = allocator.AcquireVectorTuple(TupleType::VG2);
            VectorTuple zd_dest_tuple  = allocator.AcquireVectorTuple(TupleType::VG2);

            // Dequantize 2 segments using LUTI4 VG2
            for (uint32_t segment = 0; segment < 2; ++segment) {
                nodes.push_back({
                    LUT_OP_LUTI4_VG2_S, 0, (uint8_t)segment,
                    zd_dest_tuple.base_reg,
                    zn_table_tuple.base_reg,
                    zm_packed_weights, 0
                });
            }

            allocator.ReleaseVectorTuple(zd_dest_tuple);
            allocator.ReleaseVectorTuple(zn_table_tuple);
        }

        return nodes;
    }

    void Reset() { allocator.Reset(); }
};

#endif // SME2_LUT_LOWERING_H
