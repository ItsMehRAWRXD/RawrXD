#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace rguf {

// Quantize float array to Q4 blocks. Returns number of bytes written to dst.
size_t quantize_q4(const float* src, size_t count, std::vector<uint8_t>& dst);

// Dequantize Q4 blocks to float array. Returns bytes consumed from src.
size_t dequantize_q4(const uint8_t* src, size_t count, float* dst);

} // namespace rguf
