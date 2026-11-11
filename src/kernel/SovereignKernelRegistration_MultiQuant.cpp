/*===========================================================================
 * SovereignKernelRegistration_MultiQuant.cpp
 *
 * Automatic registration of all quantization kernels (Q4/Q5/Q6/Q8)
 * with SovereignKernelRegistry
 *
 * This file registers:
 *   - Q4_K_M (existing)
 *   - Q5_K_M (new)
 *   - Q6_K (new)
 *   - Q8_0 (new)
 *
 * Registration happens automatically at startup via static initializers.
 *===========================================================================*/

#include "SovereignKernelRegistry.hpp"
#include "../bridge/Deep2_Quantized.hpp"

// External MASM kernel declarations
extern "C" {
    // Q4_K_M
    uint64_t Sovereign_Q4KM_DequantRange(const uint8_t* blocks, float* dest, uint64_t num_blocks);

    // Q5_K_M
    uint64_t Sovereign_Q5KM_DequantRange(const uint8_t* blocks, float* dest, uint64_t num_blocks);

    // Q6_K
    uint64_t Sovereign_Q6K_DequantRange(const uint8_t* blocks, float* dest, uint64_t num_blocks);

    // Q8_0 (simpler format - direct implementation in C++)
    void Sovereign_Q8_0_DequantRange(const uint8_t* blocks, float* dest, uint64_t num_blocks);
}

namespace RawrXD {
namespace Kernel {

/*===========================================================================
 * Q4_K_M Kernel Registration (existing, for completeness)
 *===========================================================================*/

static struct Q4KM_Kernel_Registrar {
    Q4KM_Kernel_Registrar() {
        QuantKernel kernel = {
            Deep2::QuantType::Q4_K_M,
            256,  // blockSize
            Sovereign_Q4KM_DequantRange,
            nullptr,  // matvec - TODO
            nullptr,  // quantize - TODO
            "1.0.0",
            true
        };

        Deep2::QuantizationRouter::Instance().RegisterKernel(kernel);

        // Also register in type-specific registry
        KernelRegistry<Deep2::DequantFunc>::Instance().Register(
            "q4_k_m_dequant",
            Sovereign_Q4KM_DequantRange,
            { "q4_k_m_dequant", "1.0.0", CPUFeature::AVX2, CPUFeature::AVX512F, 0, 0, true }
        );
    }
} g_Q4KM_Kernel_Registrar;

/*===========================================================================
 * Q5_K_M Kernel Registration
 *===========================================================================*/

static struct Q5KM_Kernel_Registrar {
    Q5KM_Kernel_Registrar() {
        QuantKernel kernel = {
            Deep2::QuantType::Q5_K_M,
            256,  // blockSize
            Sovereign_Q5KM_DequantRange,
            nullptr,  // matvec
            nullptr,  // quantize
            "1.0.0",
            true
        };

        Deep2::QuantizationRouter::Instance().RegisterKernel(kernel);

        KernelRegistry<Deep2::DequantFunc>::Instance().Register(
            "q5_k_m_dequant",
            Sovereign_Q5KM_DequantRange,
            { "q5_k_m_dequant", "1.0.0", CPUFeature::AVX2, CPUFeature::AVX512F, 0, 0, true }
        );
    }
} g_Q5KM_Kernel_Registrar;

/*===========================================================================
 * Q6_K Kernel Registration
 *===========================================================================*/

static struct Q6K_Kernel_Registrar {
    Q6K_Kernel_Registrar() {
        QuantKernel kernel = {
            Deep2::QuantType::Q6_K,
            256,  // blockSize
            Sovereign_Q6K_DequantRange,
            nullptr,  // matvec
            nullptr,  // quantize
            "1.0.0",
            true
        };

        Deep2::QuantizationRouter::Instance().RegisterKernel(kernel);

        KernelRegistry<Deep2::DequantFunc>::Instance().Register(
            "q6_k_dequant",
            Sovereign_Q6K_DequantRange,
            { "q6_k_dequant", "1.0.0", CPUFeature::AVX2, CPUFeature::AVX512F, 0, 0, true }
        );
    }
} g_Q6K_Kernel_Registrar;

/*===========================================================================
 * Q8_0 Kernel Registration (C++ implementation)
 *===========================================================================*/

// Q8_0 dequantization (simpler format)
static uint64_t Q8_0_DequantRange_Wrapper(const uint8_t* blocks, float* dest, uint64_t num_blocks) {
    // Q8_0: 32 values per block, 34 bytes per block
    // Layout: scale (4 bytes) + 32 int8 values
    const size_t BLOCK_SIZE = 32;
    const size_t BYTES_PER_BLOCK = 34;

    for (uint64_t b = 0; b < num_blocks; ++b) {
        const uint8_t* block = blocks + b * BYTES_PER_BLOCK;
        float* block_dest = dest + b * BLOCK_SIZE;

        // Read scale
        float scale;
        memcpy(&scale, block, sizeof(float));

        // Dequantize 32 int8 values
        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            int8_t val = static_cast<int8_t>(block[4 + i]);
            block_dest[i] = static_cast<float>(val) * scale;
        }
    }

    return num_blocks * BLOCK_SIZE;
}

static struct Q8_0_Kernel_Registrar {
    Q8_0_Kernel_Registrar() {
        QuantKernel kernel = {
            Deep2::QuantType::Q8_0,
            32,   // blockSize
            Q8_0_DequantRange_Wrapper,
            nullptr,  // matvec
            nullptr,  // quantize
            "1.0.0",
            false  // Not MASM-optimized yet
        };

        Deep2::QuantizationRouter::Instance().RegisterKernel(kernel);

        KernelRegistry<Deep2::DequantFunc>::Instance().Register(
            "q8_0_dequant",
            Q8_0_DequantRange_Wrapper,
            { "q8_0_dequant", "1.0.0", CPUFeature::None, CPUFeature::AVX2, 0, 0, false }
        );
    }
} g_Q8_0_Kernel_Registrar;

} // namespace Kernel
} // namespace RawrXD

/*===========================================================================
 * C API for Runtime Query
 *===========================================================================*/

extern "C" {

// Check which quantization formats are available
__declspec(dllexport)
int SovereignKernel_MultiQuant_Available(int quant_type) {
    using namespace RawrXD::Deep2;

    auto type = static_cast<QuantType>(quant_type);
    return QuantizationRouter::Instance().IsSupported(type) ? 1 : 0;
}

// Get number of registered quantization formats
__declspec(dllexport)
int SovereignKernel_MultiQuant_Count(void) {
    int count = 0;
    RawrXD::Deep2::QuantizationRouter::Instance().ListSupportedFormats(
        [&count](QuantType type, const char* name) {
            (void)type;
            (void)name;
            ++count;
        }
    );
    return count;
}

// Get format name by index
__declspec(dllexport)
const char* SovereignKernel_MultiQuant_GetName(int index) {
    int current = 0;
    const char* result = nullptr;

    RawrXD::Deep2::QuantizationRouter::Instance().ListSupportedFormats(
        [&](QuantType type, const char* name) {
            if (current == index) {
                result = RawrXD::Deep2::QuantTypeToString(type);
            }
            ++current;
        }
    );

    return result ? result : "unknown";
}

// Recommend quant format for model
__declspec(dllexport)
int SovereignKernel_MultiQuant_Recommend(uint64_t model_params, uint32_t vram_mb) {
    auto type = RawrXD::Deep2::QuantizationRouter::RecommendFormat(model_params, vram_mb);
    return static_cast<int>(type);
}

} // extern "C"
