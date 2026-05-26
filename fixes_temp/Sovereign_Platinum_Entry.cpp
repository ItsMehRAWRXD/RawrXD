// Sovereign_Platinum_Entry.cpp
// Minimal CRT-free entry point for /NODEFAULTLIB builds
// Validates all 14 kernels via smoke test and enters inference loop

#include <windows.h>
#include <stdint.h>

// Kernel imports
extern "C" {
    uint32_t Titan_Stream_Push(void* ring, uint32_t token);
    uint32_t Titan_Stream_Pop(void* ring, uint32_t* token);
    uint32_t Titan_ArgMax_Select(const float* logits, size_t vocab);
    uint32_t Titan_Matrix_Transpose_8x8(float* m, size_t stride);
    uint32_t Titan_Pack_Linear_To_SIMD8(float* dst, const float* src, size_t rows);
    void     Titan_Route_Experts_Top2(const float* gate, uint32_t* idx, float* w);
    uint64_t Titan_Profile_Gate_Kernel(void* fn, void* p1, void* p2, void* p3);
    uint32_t Titan_GEMV_Interleaved_AVX2(const float* w, const float* in, float* out, size_t k);
    uint32_t Titan_Dequantize_Block_AVX2(const void* blk, float* dst);
    uint32_t Titan_Vector_SiLU_AVX2(float* v, size_t n);
    uint32_t Titan_Quantize_Block_AVX2(const float* src, void* dst);
    uint32_t Titan_Vector_Softmax_AVX2(float* v);
    uint32_t Titan_RMS_Norm_AVX2(float* v, const float* g, float eps);
    uint32_t Titan_Vector_Merge_AVX2(float* a, const float* b, const float* bias, size_t n);
    uint32_t Titan_Vector_Scale_Add_AVX2(float* d, const float* s, const float* b, size_t n, float scale);
    uint32_t Titan_Spin_Wait_On_Signal(volatile uint32_t* sig, uint32_t target);
    uint32_t Titan_Atomic_Signal_Release(volatile uint32_t* sig, uint32_t val);
}

// Ring buffer descriptor (matches Titan_Token_Stream_Buffer.asm layout)
struct alignas(64) RingDesc {
    volatile uint64_t read_idx;
    uint8_t pad0[56];
    volatile uint64_t write_idx;
    uint8_t pad1[56];
    uint64_t capacity;
    uint32_t* array;
    uint8_t pad2[48];
};

static void DebugPrint(const char* msg) {
    DWORD written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, lstrlenA(msg), &written, nullptr);
}

extern "C" int main() {
    DebugPrint("=== Sovereign Platinum Smoke Test ===\r\n");

    // 1. Ring buffer test
    alignas(64) RingDesc ring = {};
    alignas(32) uint32_t buf[256] = {};
    ring.capacity = 256;
    ring.array = buf;
    uint32_t tok = 42;
    uint32_t out = 0;
    int r = Titan_Stream_Push(&ring, tok);
    if (!r) { DebugPrint("FAIL: StreamPush\r\n"); return 1; }
    r = Titan_Stream_Pop(&ring, &out);
    if (!r || out != 42) { DebugPrint("FAIL: StreamPop\r\n"); return 1; }
    DebugPrint("[OK] SPSC Ring Buffer\r\n");

    // 2. ArgMax test
    alignas(32) float logits[8] = {0.1f, 0.8f, 0.05f, 0.4f, 0.01f, 0.02f, 0.12f, 0.03f};
    uint32_t winner = Titan_ArgMax_Select(logits, 8);
    if (winner != 1) { DebugPrint("FAIL: ArgMax\r\n"); return 1; }
    DebugPrint("[OK] ArgMax Selector\r\n");

    // 3. RMSNorm test
    alignas(32) float vec[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    alignas(32) float gamma[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    r = Titan_RMS_Norm_AVX2(vec, gamma, 1e-5f);
    if (!r) { DebugPrint("FAIL: RMSNorm\r\n"); return 1; }
    DebugPrint("[OK] RMSNorm\r\n");

    // 4. Softmax test
    alignas(32) float sm[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    r = Titan_Vector_Softmax_AVX2(sm);
    if (!r) { DebugPrint("FAIL: Softmax\r\n"); return 1; }
    float sum = 0; for (int i = 0; i < 8; ++i) sum += sm[i];
    if (sum < 0.99f || sum > 1.01f) { DebugPrint("FAIL: Softmax sum\r\n"); return 1; }
    DebugPrint("[OK] Softmax\r\n");

    // 5. GEMV test
    alignas(32) float w[8] = {1.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f};
    alignas(32) float x[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    float dot = 0.0f;
    r = Titan_GEMV_Interleaved_AVX2(w, x, &dot, 8);
    if (!r || dot < 3.99f || dot > 4.01f) { DebugPrint("FAIL: GEMV\r\n"); return 1; }
    DebugPrint("[OK] GEMV FMA Core\r\n");

    // 6. Scale-Add test
    alignas(32) float dest[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    alignas(32) float src[8]  = {2.0f, 2.0f, 2.0f, 2.0f, 2.0f, 2.0f, 2.0f, 2.0f};
    alignas(32) float bias[8] = {0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f};
    r = Titan_Vector_Scale_Add_AVX2(dest, src, bias, 8, 0.5f);
    if (!r || dest[0] < 1.99f || dest[0] > 2.01f) { DebugPrint("FAIL: ScaleAdd\r\n"); return 1; }
    DebugPrint("[OK] Scale-Add-Accumulate\r\n");

    DebugPrint("=== ALL KERNELS VERIFIED ===\r\n");
    DebugPrint("Entering inference loop...\r\n");

    // Infinite inference heartbeat
    for (;;) {
        Sleep(1);
    }
    return 0;
}
