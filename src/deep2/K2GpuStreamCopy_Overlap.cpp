// K2GpuStreamCopy_Overlap.cpp — PrefetchWeight || GEMV (K2_GPU_COPY_COMPUTE_OVERLAP_001)
#include "K2GpuStreamCopy.hpp"
#include "GpuTransferCounters.hpp"
#include "vulkan_compute.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace Deep2 {

CPUInference::VulkanCompute* K2GpuStreamCopy_Vc();
void K2GpuStreamCopy_NoteOk(size_t n);
void K2GpuStreamCopy_NoteFail();

namespace {
bool CapWindow(CPUInference::VulkanCompute* vc, size_t bytes, size_t& outN) {
    // Prefer live pin budget; never stomp PROMOTE reuse with a shallow 512MiB.
    size_t budget = vc->WeightBudgetBytes();
    if (!budget) budget = 512ull << 20;
    if (const char* b = std::getenv("DEEP2_WEIGHT_BUDGET_MIB")) {
        long v = std::atol(b); if (v > 0) budget = (size_t)v << 20;
    }
    uint32_t nSlots = 4;
    if (const char* ns = std::getenv("DEEP2_WEIGHT_SLOTS")) {
        int v = std::atoi(ns); if (v >= 2 && v <= 16) nSlots = (uint32_t)v;
    }
    size_t slotB = bytes;
    if ((uint64_t)nSlots * (uint64_t)slotB > (uint64_t)budget)
        slotB = budget / nSlots;
    if (!slotB || !vc->EnsureWeightWindow(slotB, nSlots, budget)) return false;
    outN = bytes < slotB ? bytes : slotB;
    return true;
}

void PickTwo(const std::vector<uint8_t>* p, size_t n,
             const uint8_t*& a, size_t& na, const uint8_t*& b, size_t& nb) {
    a = b = nullptr; na = nb = 0;
    for (size_t i = 0; i < n; ++i) {
        const size_t s = p[i].size();
        if (s > na) { nb = na; b = a; na = s; a = p[i].data(); }
        else if (s > nb) { nb = s; b = p[i].data(); }
    }
    if (!b) { b = a; nb = na; }
}
} // namespace

bool K2GpuStreamCopy_UploadOverlap(const std::vector<uint8_t>* payloads, size_t n) {
    auto* vc = K2GpuStreamCopy_Vc();
    if (!vc || !payloads || !n) return false;
    const uint8_t *pa = nullptr, *pb = nullptr;
    size_t na = 0, nb = 0;
    PickTwo(payloads, n, pa, na, pb, nb);
    if (!pa || !na) { K2GpuStreamCopy_NoteFail(); return false; }

    size_t ca = 0, cb = 0;
    if (!CapWindow(vc, (std::max)(na, nb), ca)) {
        K2GpuStreamCopy_NoteFail(); return false;
    }
    ca = na < ca ? na : ca;
    cb = nb < ca ? nb : ca; // same slotB

    constexpr uint32_t kCols = 256;
    const uint32_t rowsA = (uint32_t)(std::min)(ca / (kCols * 4ull), 512ull);
    const uint32_t rowsB = (uint32_t)(std::min)(cb / (kCols * 4ull), 512ull);
    if (rowsA < 1 || rowsB < 1) { K2GpuStreamCopy_NoteFail(); return false; }
    const uint32_t H = (std::max)(rowsA, kCols);
    if (!vc->EnsureForwardArena(H, H, 1, 1, 64, 8, 2)) {
        K2GpuStreamCopy_NoteFail(); return false;
    }
    std::vector<float> zeros(H, 0.f);
    if (!vc->UploadHidden(zeros.data(), H)) {
        K2GpuStreamCopy_NoteFail(); return false;
    }

    uint32_t sa = 0, sb = 0;
    const uint64_t ops0 = GpuTransfer_Snapshot().copyOps;
    if (!vc->PrefetchWeight(pa, ca, sa)) { K2GpuStreamCopy_NoteFail(); return false; }
    if (!vc->SubmitGemvPrefetch(sa, vc->ArenaHidden(), vc->ArenaNormed(),
                                rowsA, kCols)) {
        K2GpuStreamCopy_NoteFail(); return false;
    }
    // Second prefetch while GEMV is pending → transfer||compute overlap.
    if (!vc->PrefetchWeight(pb, cb, sb)) { K2GpuStreamCopy_NoteFail(); return false; }
    if (!vc->WaitWeightUpload(sb)) { K2GpuStreamCopy_NoteFail(); return false; }
    if (!vc->FlushWeightComputes()) { K2GpuStreamCopy_NoteFail(); return false; }

    const uint64_t ops1 = GpuTransfer_Snapshot().copyOps;
    if (ops1 > ops0) {
        K2GpuStreamCopy_NoteOk(ca);
        if (ops1 > ops0 + 1) K2GpuStreamCopy_NoteOk(cb);
    } else {
        // Weight-window hit: tensors already device-resident this run.
        K2GpuStreamCopy_NoteOk(0);
    }
    return true;
}

} // namespace Deep2
