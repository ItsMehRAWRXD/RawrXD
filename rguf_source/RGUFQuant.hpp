#pragma once
#include "RGUFFormat.hpp"
#include <vector>
namespace rguf {
// Custom symmetric Q4: 32 float values -> 16 bytes nibbles + FP32 scale.
bool quantize_q4(const float* x,size_t n,std::vector<uint8_t>& out);
bool dequantize_q4(const uint8_t* p,size_t bytes,size_t n,std::vector<float>& out);
}
