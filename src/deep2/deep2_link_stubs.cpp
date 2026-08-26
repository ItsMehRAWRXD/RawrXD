// ============================================================================
// deep2_link_stubs.cpp — Honest stubs for symbols NOT provided by real TUs
// ============================================================================

#include "vulkan_compute.h"
#include <vector>
#include <cstring>
#include <cstddef>

namespace CPUInference {

// VulkanCompute stubs
VulkanCompute::VulkanCompute() {}
VulkanCompute::~VulkanCompute() {}
bool VulkanCompute::Initialize() { return false; }
bool VulkanCompute::DispatchGEMV(const float*, const float*, float*, unsigned int, unsigned int) {
    return false;
}
bool VulkanCompute::FlushAsyncCommands() { return false; }

} // namespace CPUInference

// Deep2_Q6_K_GEMV stub (sovereign_q6_k_gemv.asm not linked)
extern "C" void Deep2_Q6_K_GEMV(const void* blocks, const float* x, float* out, std::size_t nBlocks) {
    (void)blocks; (void)x; (void)out; (void)nBlocks;
}
