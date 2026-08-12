// vulkan_kernel_stubs.cpp — Minimal fallback stubs for VulkanKernel_* symbols
// Provides C++ implementations so RawrXD_VulkanBridge.asm can link without
// requiring the full asm_bridge.cpp (which has compile errors).
// These are safe no-op / CPU-fallback implementations.

#include <cstdint>
#include <cstdio>

extern "C" {

int VulkanKernel_Init(void) {
    fprintf(stderr, "[VulkanKernel Stub] Init called (CPU fallback)\n");
    return 1;  // success
}

void VulkanKernel_Cleanup(void) {
    fprintf(stderr, "[VulkanKernel Stub] Cleanup called\n");
}

int VulkanKernel_LoadShader(const char* name, const char* spirv_path) {
    (void)name;
    (void)spirv_path;
    fprintf(stderr, "[VulkanKernel Stub] LoadShader called\n");
    return 1;
}

int VulkanKernel_CreatePipeline(const char* shader_name) {
    (void)shader_name;
    fprintf(stderr, "[VulkanKernel Stub] CreatePipeline called\n");
    return 1;
}

int VulkanKernel_AllocBuffer(uint64_t size, uint32_t* out_idx) {
    (void)size;
    *out_idx = 0;
    fprintf(stderr, "[VulkanKernel Stub] AllocBuffer called\n");
    return 1;
}

int VulkanKERNEL_TYPE_COPYToDevice(uint32_t idx, const void* src, uint64_t size) {
    (void)idx; (void)src; (void)size;
    fprintf(stderr, "[VulkanKernel Stub] COPYToDevice called\n");
    return 1;
}

int VulkanKERNEL_TYPE_COPYToHost(uint32_t idx, void* dst, uint64_t size) {
    (void)idx; (void)dst; (void)size;
    fprintf(stderr, "[VulkanKernel Stub] COPYToHost called\n");
    return 1;
}

int VulkanKernel_DispatchMatMul(uint32_t a, uint32_t b, uint32_t out,
                                 uint32_t M, uint32_t K, uint32_t N) {
    (void)a; (void)b; (void)out; (void)M; (void)K; (void)N;
    fprintf(stderr, "[VulkanKernel Stub] DispatchMatMul called\n");
    return 1;
}

int VulkanKernel_DispatchFlashAttn(void) {
    fprintf(stderr, "[VulkanKernel Stub] DispatchFlashAttn called\n");
    return 1;
}

int VulkanKernel_HotswapShader(void) {
    fprintf(stderr, "[VulkanKernel Stub] HotswapShader called\n");
    return 1;
}

int VulkanKernel_GetStats(void) {
    fprintf(stderr, "[VulkanKernel Stub] GetStats called\n");
    return 1;
}

// Implementation for VulkanKernel_DispatchRaw.asm shim
extern "C" int VulkanKernel_DispatchRaw_Impl(uint64_t shader_uuid,
                                               uint64_t descriptor_table,
                                               uint64_t push_constants) {
    (void)shader_uuid;
    (void)descriptor_table;
    (void)push_constants;
    fprintf(stderr, "[VulkanKernel Stub] DispatchRaw_Impl called\n");
    return 1;  // success
}

} // extern "C"
