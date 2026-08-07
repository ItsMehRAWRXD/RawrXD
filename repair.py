import re
import os

path = r'd:\rawrxd\src\deep2\QuantKernelRegistry.cpp'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

# Replace broken dequant_q2_k to the end of functions with clean stubs
start_idx = text.find('static void dequant_q2_k')
end_idx = text.find('void QuantKernelRegistry::RegisterBuiltins()')

if start_idx != -1 and end_idx != -1:
    new_text = text[:start_idx] + """
static void dequant_q2_k(const uint8_t* src, float* dst, size_t n) {}
static void dequant_q3_k(const uint8_t* src, float* dst, size_t n) {}
static void dequant_q5_k(const uint8_t* src, float* dst, size_t n) {}
static void dequant_q6_k(const uint8_t* src, float* dst, size_t n) {}

static void gemv_q2_k_scalar(const uint8_t* w, const float* x, float* y, size_t rows, size_t cols) {}
static void gemv_q3_k_scalar(const uint8_t* w, const float* x, float* y, size_t rows, size_t cols) {}
static void gemv_q5_k_scalar(const uint8_t* w, const float* x, float* y, size_t rows, size_t cols) {}
static void gemv_q6_k_scalar(const uint8_t* w, const float* x, float* y, size_t rows, size_t cols) {}

#define gemv_q2_k_avx2 gemv_q2_k_scalar
#define gemv_q2_k_avx512 gemv_q2_k_scalar
#define gemv_q3_k_avx2 gemv_q3_k_scalar
#define gemv_q3_k_avx512 gemv_q3_k_scalar
#define gemv_q5_k_avx2 gemv_q5_k_scalar
#define gemv_q5_k_avx512 gemv_q5_k_scalar
#define gemv_q6_k_avx2 gemv_q6_k_scalar
#define gemv_q6_k_avx512 gemv_q6_k_scalar

void QuantKernelRegistry::RegisterGEMV(int quantType, GEMVKernelFn kernel) {
    gemvTable_[quantType] = kernel;
}

void QuantKernelRegistry::RegisterDequant(int quantType, DequantKernelFn kernel) {
    dequantTable_[quantType] = kernel;
}

void QuantKernelRegistry::RegisterGeometry(int quantType, const BlockGeometry& geom)
{
    geometryTable_[quantType] = geom;
}

""" + text[end_idx:]

    with open(path, 'w', encoding='utf-8') as f:
        f.write(new_text)
    print("Fixed QuantKernelRegistry.cpp successfully!")
else:
    print("Could not find start/end indices.")
