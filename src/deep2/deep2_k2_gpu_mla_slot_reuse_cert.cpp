// deep2_k2_gpu_mla_slot_reuse_cert.cpp — K2_GPU_MLA_SLOT_REUSE_001
#include "GpuTransferCounters.hpp"
#include "vulkan_compute.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static void SyncEnv(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_SLOT_REUSE_001",
                     nullptr);
#endif
    printf("K2_GPU_MLA_SLOT_REUSE_001\n");
    SyncEnv("DEEP2_WEIGHT_PIN", "1");
    SyncEnv("DEEP2_WEIGHT_BUDGET_MIB", "512");
    SyncEnv("DEEP2_WEIGHT_MODE", "CACHE");

    CPUInference::VulkanCompute vc;
    if (!vc.Initialize()) {
        printf("K2_GPU_MLA_SLOT_REUSE_001=FAIL vulkan_init\n");
#ifdef _WIN32
        _exit(2);
#else
        return 2;
#endif
    }
    const uint32_t rows = 256, cols = 256;
    const size_t need = (size_t)rows * ((size_t)cols / 256u) * 144u;
    std::vector<uint8_t> packed(need, 0);
    for (size_t i = 0; i < need; ++i)
        packed[i] = (uint8_t)((i * 17u) & 0xFFu);
    std::vector<float> x(cols, 0.01f), y(rows, 0.f);
    const uint64_t pinKey = 0x4D4C415201ull; // "MLAR\1"

    Deep2::GpuTransfer_Reset();
    const uint64_t hits0 = vc.GemvWeightHits();
    const uint64_t up0 = vc.GemvWeightUploads();
    const bool a = vc.DispatchGEMVPacked(packed.data(), packed.size(), x.data(),
                                         y.data(), rows, cols, pinKey);
    const uint64_t hits1 = vc.GemvWeightHits();
    const uint64_t up1 = vc.GemvWeightUploads();
    const auto g1 = Deep2::GpuTransfer_Snapshot();

    const bool b = vc.DispatchGEMVPacked(packed.data(), packed.size(), x.data(),
                                         y.data(), rows, cols, pinKey);
    const uint64_t hits2 = vc.GemvWeightHits();
    const uint64_t up2 = vc.GemvWeightUploads();
    const auto g2 = Deep2::GpuTransfer_Snapshot();

    // Third call different key → must upload again (or reject), not false hit
    const bool c = vc.DispatchGEMVPacked(packed.data(), packed.size(), x.data(),
                                         y.data(), rows, cols, pinKey + 1);
    const uint64_t up3 = vc.GemvWeightUploads();

    const bool firstMiss = a && (up1 > up0) && (hits1 == hits0);
    const bool secondHit = b && (hits2 > hits1) && (up2 == up1);
    const bool keySplit = c && (up3 > up2);
    const bool xferHit = g2.weightHits > g1.weightHits;

    printf("A_OK=%d B_OK=%d C_OK=%d\n", a ? 1 : 0, b ? 1 : 0, c ? 1 : 0);
    printf("UP=%llu→%llu→%llu→%llu HITS=%llu→%llu→%llu\n",
           (unsigned long long)up0, (unsigned long long)up1,
           (unsigned long long)up2, (unsigned long long)up3,
           (unsigned long long)hits0, (unsigned long long)hits1,
           (unsigned long long)hits2);
    printf("FIRST_MISS=%d SECOND_HIT=%d KEY_SPLIT=%d XFER_HIT=%d\n",
           firstMiss ? 1 : 0, secondHit ? 1 : 0, keySplit ? 1 : 0,
           xferHit ? 1 : 0);

    const bool pass = firstMiss && secondHit && keySplit && xferHit;
    printf("K2_GPU_MLA_SLOT_REUSE_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_SLOT_REUSE_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "FIRST_MISS=%d SECOND_HIT=%d KEY_SPLIT=%d\n", firstMiss,
                secondHit, keySplit);
        fprintf(f, "K2_GPU_MLA_SLOT_REUSE_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    vc.Cleanup();
#ifdef _WIN32
    _exit(pass ? 0 : 2);
#else
    return pass ? 0 : 2;
#endif
}
