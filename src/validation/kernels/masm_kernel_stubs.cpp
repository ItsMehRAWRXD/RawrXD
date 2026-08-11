// masm_kernel_stubs.cpp - Stub wrappers for renamed MASM kernels
// Maps old symbol names to new fixed versions

#include <cstdint>

extern "C" {
    int MASM_Silu_Activation_AVX512_Fixed(float* data, size_t data_size);

    int MASM_Silu_Activation_AVX512(float* data, size_t data_size) {
        return MASM_Silu_Activation_AVX512_Fixed(data, data_size);
    }
}
