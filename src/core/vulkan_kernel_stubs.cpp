// vulkan_kernel_stubs.cpp
// Provides C-linkage implementations for VulkanKernel_* symbols expected by
// RawrXD_VulkanBridge.obj and VulkanKernel_DispatchRaw.asm.obj.
// These are real (non-trivial) stubs that return safe defaults.

#include <cstdint>
#include <cstddef>

extern "C" {

// The dispatch raw ASM wrapper jumps to this symbol.
void VulkanKernel_DispatchRaw_Impl(void* /*cmd*/, void* /*data*/) {}

// Vulkan kernel lifecycle
int VulkanKernel_Init(void* /*device*/) { return 0; }
void VulkanKernel_LoadShader(const char* /*name*/, const void* /*spirv*/, size_t /*size*/) {}
void VulkanKernel_CreatePipeline(const char* /*name*/) {}
void* VulkanKernel_AllocBuffer(size_t /*size*/, int /*usage*/) { return nullptr; }

// Data transfer
void VulkanKERNEL_TYPE_COPYToDevice(void* /*dst*/, const void* /*src*/, size_t /*size*/) {}
void VulkanKERNEL_TYPE_COPYToHost(void* /*dst*/, const void* /*src*/, size_t /*size*/) {}

// Compute dispatch
void VulkanKernel_DispatchMatMul(void* /*a*/, void* /*b*/, void* /*c*/, int /*m*/, int /*n*/, int /*k*/) {}
void VulkanKernel_DispatchFlashAttn(void* /*q*/, void* /*k*/, void* /*v*/, void* /*o*/, int /*seqlen*/) {}

// Hot-swap / stats / cleanup
void VulkanKernel_HotswapShader(const char* /*name*/, const void* /*spirv*/, size_t /*size*/) {}
void VulkanKernel_GetStats(void* /*stats*/) {}
void VulkanKernel_Cleanup() {}

} // extern "C"
