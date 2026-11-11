// ============================================================================
// optimizer/sme2_packing_optimizer.hpp - SME2 INT2/INT4 Memory Swizzler
// Converts raw quantized weights into hardware-swizzled byte streams
// matched to ZT0 table indexing for LUTI2/LUTI4
// ============================================================================

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <cstring>

#ifndef SME2_PACKING_OPTIMIZER_H
#define SME2_PACKING_OPTIMIZER_H

enum class QuantPrecision {
    INT2 = 2, // 4 indices per byte (LUTI2, imm3 = 0..7)
    INT4 = 4  // 2 indices per byte (LUTI4, imm2 = 0..3)
};

struct SwizzledWeightBuffer {
    std::vector<uint8_t> data;
    size_t               original_rows;
    size_t               original_cols;
    QuantPrecision       precision;
    uint32_t             svl_bytes; // Streaming Vector Length in bytes
};

class SME2LayoutOptimizer {
public:
    // Swizzle INT4 weights for LUTI4 #imm2=0..3 contiguous nibble access
    static SwizzledWeightBuffer OptimizeINT4Layout(
        const int8_t* raw_int4_matrix,
        size_t rows,
        size_t cols,
        uint32_t svl_bytes = 64)
    {
        if (cols % (svl_bytes * 2) != 0) {
            throw std::runtime_error(
                "Column count must align to 2x SVL bytes for INT4 granules.");
        }

        SwizzledWeightBuffer result;
        result.original_rows = rows;
        result.original_cols = cols;
        result.precision     = QuantPrecision::INT4;
        result.svl_bytes     = svl_bytes;

        size_t total_packed_bytes = (rows * cols) / 2;
        result.data.resize(total_packed_bytes);

        size_t dest_idx = 0;
        for (size_t r = 0; r < rows; ++r) {
            for (size_t c_chunk = 0; c_chunk < cols; c_chunk += (svl_bytes * 2)) {
                // Pack 128 INT4 elements into 64 bytes with swizzled nibble placement
                for (size_t byte_off = 0; byte_off < svl_bytes; ++byte_off) {
                    size_t elem_low  = (r * cols) + c_chunk + byte_off;
                    size_t elem_high = elem_low + svl_bytes;

                    uint8_t low_nibble  = static_cast<uint8_t>(raw_int4_matrix[elem_low])  & 0x0F;
                    uint8_t high_nibble = static_cast<uint8_t>(raw_int4_matrix[elem_high]) & 0x0F;

                    // Low nibble -> imm2=0, High nibble -> imm2=1
                    result.data[dest_idx++] = low_nibble | (high_nibble << 4);
                }
            }
        }
        return result;
    }

    // Swizzle INT2 weights for LUTI2 #imm3=0..3 contiguous 2-bit field access
    static SwizzledWeightBuffer OptimizeINT2Layout(
        const int8_t* raw_int2_matrix,
        size_t rows,
        size_t cols,
        uint32_t svl_bytes = 64)
    {
        if (cols % (svl_bytes * 4) != 0) {
            throw std::runtime_error(
                "Column count must align to 4x SVL bytes for INT2 granules.");
        }

        SwizzledWeightBuffer result;
        result.original_rows = rows;
        result.original_cols = cols;
        result.precision     = QuantPrecision::INT2;
        result.svl_bytes     = svl_bytes;

        size_t total_packed_bytes = (rows * cols) / 4;
        result.data.resize(total_packed_bytes);

        size_t dest_idx = 0;
        for (size_t r = 0; r < rows; ++r) {
            for (size_t c_chunk = 0; c_chunk < cols; c_chunk += (svl_bytes * 4)) {
                // Interleave 4 contiguous 64-element vectors into single 64-byte stream
                for (size_t byte_off = 0; byte_off < svl_bytes; ++byte_off) {
                    size_t base = (r * cols) + c_chunk + byte_off;

                    uint8_t p0 = static_cast<uint8_t>(raw_int2_matrix[base + 0 * svl_bytes]) & 0x03;
                    uint8_t p1 = static_cast<uint8_t>(raw_int2_matrix[base + 1 * svl_bytes]) & 0x03;
                    uint8_t p2 = static_cast<uint8_t>(raw_int2_matrix[base + 2 * svl_bytes]) & 0x03;
                    uint8_t p3 = static_cast<uint8_t>(raw_int2_matrix[base + 3 * svl_bytes]) & 0x03;

                    result.data[dest_idx++] = p0 | (p1 << 2) | (p2 << 4) | (p3 << 6);
                }
            }
        }
        return result;
    }

    // Build a 512-bit ZT0 dequantization table from FP32 centroids
    static std::vector<uint8_t> BuildZT0Table(const float* fp32_centroids, size_t count) {
        if (count != 16) {
            throw std::runtime_error("ZT0 table requires exactly 16 FP32 values.");
        }
        std::vector<uint8_t> table(64);
        memcpy(table.data(), fp32_centroids, 64);
        return table;
    }
};

#endif // SME2_PACKING_OPTIMIZER_H
