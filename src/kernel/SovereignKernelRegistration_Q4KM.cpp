/*===========================================================================
 * SovereignKernelRegistration_Q4KM.cpp
 * 
 * Automatic registration of Q4_K_M kernels with SovereignKernelRegistry
 * 
 * This file is linked into the runtime and automatically registers
 * all Q4_K_M kernel variants at startup.
 *===========================================================================*/

#include "SovereignKernelRegistry.hpp"
#include "../bridge/Deep2_Q4KM.hpp"

// External MASM kernel declarations
extern "C" {
    uint64_t Sovereign_Q4KM_DequantBlock_AVX512(const uint8_t* block, float* dest);
    uint64_t Sovereign_Q4KM_DequantBlock_AVX2(const uint8_t* block, float* dest);
    uint64_t Sovereign_Q4KM_DequantRange(const uint8_t* blocks, float* dest, uint64_t num_blocks);
    void Sovereign_Q4KM_ExtractSubBlock_Scalar(const uint8_t* block, float* dest, uint64_t sub_block_index);
}

namespace RawrXD {
namespace Kernel {

/*===========================================================================
 * Q4_K_M Kernel Registration
 *===========================================================================*/

// Register AVX-512 variant
static struct Q4KM_AVX512_Registrar {
    Q4KM_AVX512_Registrar() {
        KernelInfo info = {
            "q4_k_m_dequant_avx512",
            "1.0.0",
            CPUFeature::AVX512F,
            CPUFeature::AVX512F | CPUFeature::AVX512VL,
            0, 0, true
        };
        
        // Wrap the block function to match the range signature
        auto wrapper = [](const uint8_t* blocks, float* dest, uint64_t num_blocks) -> uint64_t {
            uint64_t total = 0;
            for (uint64_t i = 0; i < num_blocks; ++i) {
                total += Sovereign_Q4KM_DequantBlock_AVX512(
                    blocks + i * 144,  // Q4KMBlock size
                    dest + i * 256
                );
            }
            return total;
        };
        
        Q4KMRegistry().Register("q4_k_m_dequant_avx512", wrapper, info);
    }
} g_Q4KM_AVX512_Registrar;

// Register AVX2 variant
static struct Q4KM_AVX2_Registrar {
    Q4KM_AVX2_Registrar() {
        KernelInfo info = {
            "q4_k_m_dequant_avx2",
            "1.0.0",
            CPUFeature::AVX2,
            CPUFeature::AVX2,
            0, 0, true
        };
        
        auto wrapper = [](const uint8_t* blocks, float* dest, uint64_t num_blocks) -> uint64_t {
            uint64_t total = 0;
            for (uint64_t i = 0; i < num_blocks; ++i) {
                total += Sovereign_Q4KM_DequantBlock_AVX2(
                    blocks + i * 144,
                    dest + i * 256
                );
            }
            return total;
        };
        
        Q4KMRegistry().Register("q4_k_m_dequant_avx2", wrapper, info);
    }
} g_Q4KM_AVX2_Registrar;

// Register generic variant (auto-dispatch)
static struct Q4KM_Generic_Registrar {
    Q4KM_Generic_Registrar() {
        KernelInfo info = {
            "q4_k_m_dequant",
            "1.0.0",
            CPUFeature::None,
            CPUFeature::AVX512F,
            0, 0, false  // Not optimized - dispatches to best
        };
        
        // This version auto-detects and dispatches
        auto dispatcher = [](const uint8_t* blocks, float* dest, uint64_t num_blocks) -> uint64_t {
            return Sovereign_Q4KM_DequantRange(blocks, dest, num_blocks);
        };
        
        Q4KMRegistry().Register("q4_k_m_dequant", dispatcher, info);
    }
} g_Q4KM_Generic_Registrar;

} // namespace Kernel
} // namespace RawrXD

/*===========================================================================
 * C API for Runtime Query
 *===========================================================================*/

extern "C" {

// Get the best Q4_K_M dequant kernel for current CPU
__declspec(dllexport)
RawrXD::Kernel::Q4KMDequantFunc SovereignKernel_GetQ4KMDequant(void) {
    return RawrXD::Kernel::GetQ4KMDequantKernel();
}

// Check if Q4_K_M kernels are registered
__declspec(dllexport)
int SovereignKernel_Q4KM_Available(void) {
    auto kernel = RawrXD::Kernel::Q4KMRegistry().Get("q4_k_m_dequant");
    return (kernel != nullptr) ? 1 : 0;
}

// Get Q4_K_M kernel info
__declspec(dllexport)
const char* SovereignKernel_Q4KM_GetVersion(void) {
    auto info = RawrXD::Kernel::Q4KMRegistry().GetInfo("q4_k_m_dequant");
    return info ? info->version : "not_registered";
}

// Benchmark Q4_K_M kernel
__declspec(dllexport)
double SovereignKernel_Q4KM_Benchmark(uint64_t num_blocks) {
    using namespace RawrXD::Kernel;
    
    auto kernel = GetQ4KMDequantKernel();
    if (!kernel) return 0.0;
    
    // Allocate test data
    std::vector<uint8_t> blocks(num_blocks * 144);
    std::vector<float> output(num_blocks * 256);
    
    // Fill with test pattern
    for (size_t i = 0; i < blocks.size(); ++i) {
        blocks[i] = static_cast<uint8_t>(i % 256);
    }
    
    // Warmup
    for (int i = 0; i < 10; ++i) {
        kernel(blocks.data(), output.data(), num_blocks);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    const int iterations = 100;
    for (int i = 0; i < iterations; ++i) {
        kernel(blocks.data(), output.data(), num_blocks);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double seconds = duration.count() / 1e6;
    double values_per_second = (num_blocks * 256.0 * iterations) / seconds;
    
    return values_per_second / 1e9;  // Return GB/s
}

} // extern "C"
