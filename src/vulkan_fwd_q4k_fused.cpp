// vulkan_fwd_q4k_fused.cpp — fused Q4_K + O_PROJ + QKV/KVA shared-x
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include "K2MlaOProjTiming.hpp"
#include "K2MlaQkvTiming.hpp"
#include <cstring>
#include <cstdlib>
#ifdef _WIN32
#include <profileapi.h>
#endif

namespace CPUInference {
namespace {
uint64_t ONowUs() {
#ifdef _WIN32
    static LARGE_INTEGER f{};
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart * 1000000ull) / (uint64_t)f.QuadPart);
#else
    return 0;
#endif
}
} // namespace

void VulkanCompute::GemvReuseInputNext() { gemv_reuse_in_next_ = true; }

void VulkanCompute::GemvFuseResidualNext(const float* residual) {
    gemv_residual_add_ = residual;
}

uint64_t VulkanCompute::GemvInputReuseHits() const { return gemv_in_reuse_hits_; }

bool VulkanCompute::EnsureQ4kFusedPipeline() {
    return CreateGemvPipe("gemv_q4k_fused.spv", q4k_fused_pipe_);
}

bool VulkanCompute::EnsureQ4kOprojPipeline() {
    return CreateGemvPipe("gemv_q4k_oproj.spv", q4k_oproj_pipe_);
}

bool VulkanCompute::EnsureQ4kKvaPipeline() {
    return CreateGemvPipe("gemv_q4k_kva.spv", q4k_kva_pipe_);
}

bool VulkanCompute::DispatchGEMVFusedQ4KT(const void* packed, size_t bytes,
                                          const float* input, float* output,
                                          uint32_t rows, uint32_t cols,
                                          uint64_t pinKey) {
    const uint8_t tag = (uint8_t)(pinKey & 0xffu);
    const bool isOproj = (tag == 6u);
    const bool isQShared =
        (tag == 1u || tag == 2u) && (cols % 256u) == 0u;
    const bool isKva =
        (tag == 3u) && (cols % 256u) == 0u && rows > 0u;
    const bool useSharedX = isOproj || isQShared;
    const bool isQkv = (tag >= 1u && tag <= 5u);
    if (isKva) {
        if (!EnsureQ4kKvaPipeline()) return false;
    } else if (useSharedX) {
        if (!EnsureQ4kOprojPipeline()) return false;
    } else if (!EnsureQ4kFusedPipeline()) {
        return false;
    }
    if (!packed || !input || !output || !bytes) return false;
    ++gemv_attempts_;
    const size_t inB = (size_t)cols * 4;
    const uint32_t nblk = cols >> 8;
    const uint32_t colTileBlocks = 4u; // 1024 cols
    const uint32_t nColTiles =
        isKva ? ((nblk + colTileBlocks - 1u) / colTileBlocks) : 1u;
    const size_t outB = isKva ? (size_t)rows * nColTiles * 4u
                              : (size_t)rows * 4u;
    if (!EnsureHostIo(inB, outB)) return false;

    uint64_t uploadUs = 0, readbackUs = 0, kernelUs = 0;
    uint64_t inUpB = 0;
    const bool timeIo = isOproj || isQkv;

    const bool reuseIn =
        gemv_reuse_in_next_ && gemv_in_live_cols_ == cols && gemv_in_buf_;
    gemv_reuse_in_next_ = false;
    if (reuseIn) {
        ++gemv_in_reuse_hits_;
    } else {
        const uint64_t tu0 = timeIo ? ONowUs() : 0;
        void* mapped = nullptr;
        vkMapMemory(device_, gemv_in_mem_, 0, inB, 0, &mapped);
        std::memcpy(mapped, input, inB);
        vkUnmapMemory(device_, gemv_in_mem_);
        gemv_in_live_cols_ = cols;
        inUpB = inB;
        if (timeIo) uploadUs = ONowUs() - tu0;
    }
    VkBuffer wbuf = nullptr;
    if (WantWeightPin()) {
        if (!EnsurePinnedPackedWeight(packed, bytes, rows, cols, wbuf, pinKey))
            return false;
    } else {
        if (!ww_active_ || bytes > ww_slot_bytes_) {
            size_t budget = ww_budget_bytes_ ? ww_budget_bytes_
                                            : ((size_t)512 << 20);
            const char* b = std::getenv("DEEP2_WEIGHT_BUDGET_MIB");
            if (b && *b) budget = (size_t)std::atoi(b) << 20;
            uint32_t nSlots = ww_slot_count_ ? ww_slot_count_ : 8;
            const char* ns = std::getenv("DEEP2_WEIGHT_SLOTS");
            if (ns && *ns && !ww_active_) nSlots = (uint32_t)std::atoi(ns);
            if (nSlots < 2) nSlots = 2;
            if (nSlots > 128) nSlots = 128;
            size_t slotB = bytes;
            if (ww_slot_bytes_ && ww_slot_bytes_ > slotB) slotB = ww_slot_bytes_;
            if (!EnsureWeightWindow(slotB, nSlots, budget)) return false;
        }
        if (!StreamWeightToSlot(packed, bytes, wbuf)) return false;
    }

    VkPipeline pipe = isKva ? q4k_kva_pipe_
                    : (useSharedX ? q4k_oproj_pipe_ : q4k_fused_pipe_);
    const uint32_t rowTile = isKva ? 16u : (useSharedX ? 64u : 4u);
    const uint32_t rowTiles = (rows + rowTile - 1u) / rowTile;
    const uint32_t groups = isKva ? (rowTiles * nColTiles) : rowTiles;
    const uint64_t tk0 = timeIo ? ONowUs() : 0;
    if (isKva) {
        uint32_t pc[4] = {rows, cols, nColTiles, colTileBlocks};
        if (!BindGemvStoragePc(wbuf, bytes, gemv_in_buf_, inB, gemv_out_buf_,
                               outB, pipe, pc, 4u, groups))
            return false;
    } else if (!BindGemvStorage(wbuf, bytes, gemv_in_buf_, inB, gemv_out_buf_,
                                outB, pipe, rows, cols, groups)) {
        return false;
    }
    if (timeIo) kernelUs = ONowUs() - tk0;

    const float* residual = gemv_residual_add_;
    gemv_residual_add_ = nullptr;
    const uint64_t tr0 = timeIo ? ONowUs() : 0;
    void* mapped = nullptr;
    vkMapMemory(device_, gemv_out_mem_, 0, outB, 0, &mapped);
    if (isKva) {
        const float* part = static_cast<const float*>(mapped);
        for (uint32_t r = 0; r < rows; ++r) {
            float s = 0.f;
            for (uint32_t t = 0; t < nColTiles; ++t)
                s += part[r * nColTiles + t];
            output[r] = s;
        }
    } else if (residual && isOproj) {
        const float* src = static_cast<const float*>(mapped);
        for (uint32_t i = 0; i < rows; ++i)
            output[i] = residual[i] + src[i];
    } else {
        std::memcpy(output, mapped, (size_t)rows * 4u);
    }
    vkUnmapMemory(device_, gemv_out_mem_);
    if (timeIo) readbackUs = ONowUs() - tr0;

    if (isOproj) {
        Deep2::OProj_NoteIo(uploadUs, readbackUs, inUpB, (size_t)rows * 4u,
                            residual ? 1 : 0);
        Deep2::OProj_NoteTag6(rows, cols, groups, kernelUs, true);
        ++q4k_oproj_ops_;
    } else if (isQkv) {
        Deep2::Qkv_NoteDispatch(tag, uploadUs, readbackUs, kernelUs,
                                (size_t)rows * 4u);
        if (isQShared || isKva)
            Deep2::Qkv_NoteSharedX(tag, rows, cols, groups, kernelUs);
        if (isKva) Deep2::Qkv_NoteKvaColSplit(nColTiles, groups, kernelUs);
        ++q4k_fused_ops_;
        if (isQShared || isKva) ++q4k_oproj_ops_;
    } else {
        ++q4k_fused_ops_;
    }
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
