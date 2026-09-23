#pragma once
#include <cstddef>

extern "C" {

// CPUID-based AVX-512 feature detection
// Returns 1 if AVX-512F is available, 0 otherwise
unsigned int rawr_cpu_has_avx512();

// Optimized memory streaming with AVX-512 when available
// Falls back to standard memcpy if AVX-512 is not present
void RawrXD_StreamToGPU_AVX512(void* dst, const void* src, size_t bytes);

} // extern "C"
