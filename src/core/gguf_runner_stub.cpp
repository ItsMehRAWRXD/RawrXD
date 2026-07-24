// ============================================================================
// gguf_runner_stub.cpp - Stub implementations for GGUFRunner methods
// ============================================================================

#include <string>
#include <windows.h>
#include <string>

class GGUFRunner {
public:
    void tokenChunkGenerated(const std::string& chunk) {
        (void)chunk;
        OutputDebugStringA("[GGUFRunner] tokenChunkGenerated stub called\n");
    }

    void inferenceComplete(bool success) {
        (void)success;
        OutputDebugStringA("[GGUFRunner] inferenceComplete stub called\n");
    }

    void modelLoaded(const std::string& path, int64_t size) {
        (void)path;
        (void)size;
        OutputDebugStringA("[GGUFRunner] modelLoaded stub called\n");
    }
};

// ASM kernel stubs
extern "C" {

void matmul_kernel_avx2(const float* a, const float* b, float* c, int m, int n, int k) {
    (void)a;
    (void)b;
    (void)c;
    (void)m;
    (void)n;
    (void)k;
    OutputDebugStringA("[ASM] matmul_kernel_avx2 stub called\n");
}

void ggml_gemm_q4_0(const void* a, const void* b, void* c, int m, int n, int k) {
    (void)a;
    (void)b;
    (void)c;
    (void)m;
    (void)n;
    (void)k;
    OutputDebugStringA("[ASM] ggml_gemm_q4_0 stub called\n");
}

} // extern "C"
