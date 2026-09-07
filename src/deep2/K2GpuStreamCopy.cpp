// K2GpuStreamCopy.cpp — sync StreamWeightToSlot path (K2_GPU_STREAM_COPY_001)
#include "K2GpuStreamCopy.hpp"
#include "GpuTransferCounters.hpp"
#include "vulkan_compute.h"
#include <cstdlib>
#include <cstring>

namespace Deep2 {
namespace {
CPUInference::VulkanCompute* g_vc = nullptr;
uint64_t g_ops = 0, g_bytes = 0, g_fail = 0;
}
CPUInference::VulkanCompute* K2GpuStreamCopy_Vc() { return g_vc; }
void K2GpuStreamCopy_NoteOk(size_t n) { ++g_ops; g_bytes += n; }
void K2GpuStreamCopy_NoteFail() { ++g_fail; }

bool K2GpuStreamCopy_Wanted() {
    const char* e = std::getenv("DEEP2_K2_GPU_STREAM_COPY");
    return e && e[0] == '1';
}
bool K2GpuStreamCopy_OverlapWanted() {
    if (!K2GpuStreamCopy_Wanted()) return false;
    const char* ov = std::getenv("DEEP2_WEIGHT_OVERLAP");
    return !(ov && ov[0] == '0');
}

void K2GpuStreamCopy_Bind(CPUInference::VulkanCompute* vc) { g_vc = vc; }
void K2GpuStreamCopy_Reset() { g_ops = g_bytes = g_fail = 0; }
uint64_t K2GpuStreamCopy_UploadOps() { return g_ops; }
uint64_t K2GpuStreamCopy_UploadBytes() { return g_bytes; }
uint64_t K2GpuStreamCopy_FailOps() { return g_fail; }

bool K2GpuStreamCopy_UploadOverlap(const std::vector<uint8_t>* payloads, size_t n);

static bool EnsureWindow(size_t bytes, size_t& outN) {
    // Prefer live pin budget; never fall back to a shallow 512MiB that
    // forces slot rebuilds under PROMOTE_GPU_MLA_REUSE.
    size_t budget = g_vc->WeightBudgetBytes();
    if (!budget) budget = 512ull << 20;
    if (const char* b = std::getenv("DEEP2_WEIGHT_BUDGET_MIB")) {
        long v = std::atol(b);
        if (v > 0) budget = (size_t)v << 20;
    }
    uint32_t nSlots = 4;
    if (const char* ns = std::getenv("DEEP2_WEIGHT_SLOTS")) {
        int v = std::atoi(ns); if (v >= 2 && v <= 16) nSlots = (uint32_t)v;
    }
    size_t slotB = bytes;
    if ((uint64_t)nSlots * (uint64_t)slotB > (uint64_t)budget)
        slotB = budget / nSlots;
    if (!slotB || !g_vc->EnsureWeightWindow(slotB, nSlots, budget)) return false;
    outN = bytes < slotB ? bytes : slotB;
    return true;
}

static bool UploadSync(const void* data, size_t bytes) {
    if (!g_vc || !data || !bytes) return false;
    size_t n = 0;
    if (!EnsureWindow(bytes, n)) { ++g_fail; return false; }
    VkBuffer out = nullptr;
    if (!g_vc->StreamWeightToSlot(data, n, out) || !out) {
        ++g_fail; return false;
    }
    // Content-hit returns true without a new vkCmdCopy — that is success,
    // not a failed upload. Never ReleaseWeightWindow on hit (destroys slots).
    ++g_ops; g_bytes += n;
    return true;
}

bool K2GpuStreamCopy_UploadLargest(const std::vector<uint8_t>* payloads, size_t n) {
    if (!payloads || !n || !K2GpuStreamCopy_Wanted() || !g_vc) return false;
    if (K2GpuStreamCopy_OverlapWanted())
        return K2GpuStreamCopy_UploadOverlap(payloads, n);
    size_t best = 0; const uint8_t* p = nullptr;
    for (size_t i = 0; i < n; ++i) {
        if (payloads[i].size() > best) {
            best = payloads[i].size(); p = payloads[i].data();
        }
    }
    return p && UploadSync(p, best);
}

void K2GpuStreamCopy_Emit(FILE* f) {
    if (!f) f = stdout;
    fprintf(f, "K2_GPU_STREAM_COPY_WANTED=%u\n", K2GpuStreamCopy_Wanted() ? 1u : 0u);
    fprintf(f, "K2_GPU_STREAM_OVERLAP_WANTED=%u\n",
            K2GpuStreamCopy_OverlapWanted() ? 1u : 0u);
    fprintf(f, "K2_GPU_STREAM_COPY_BOUND=%u\n", g_vc ? 1u : 0u);
    fprintf(f, "K2_GPU_STREAM_UPLOAD_OPS=%llu\n", (unsigned long long)g_ops);
    fprintf(f, "K2_GPU_STREAM_UPLOAD_BYTES=%llu\n", (unsigned long long)g_bytes);
    fprintf(f, "K2_GPU_STREAM_UPLOAD_FAIL=%llu\n", (unsigned long long)g_fail);
    fflush(f);
}

} // namespace Deep2
