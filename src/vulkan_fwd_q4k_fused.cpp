// vulkan_fwd_q4k_fused.cpp — fused Q4_K + O_PROJ + QKV/KVA shared-x
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include "K2MlaOProjTiming.hpp"
#include "K2MlaQkvTiming.hpp"
#include "lavapath/LiveInGenTune.hpp"
#include <atomic>
#include <cstdio>
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
uint32_t SxIdx(uint32_t rows) {
    return rows == 32u ? 0u : rows == 64u ? 1u : rows == 128u ? 2u
                       : rows == 256u     ? 3u
                                         : 0xffffffffu;
}
} // namespace

void VulkanCompute::GemvReuseInputNext() { gemv_reuse_in_next_ = true; }
void VulkanCompute::GemvFuseResidualNext(const float* residual) {
    gemv_residual_add_ = residual;
}
uint64_t VulkanCompute::GemvInputReuseHits() const {
    return gemv_in_reuse_hits_;
}

bool VulkanCompute::EnsureQ4kFusedPipeline() {
    return CreateGemvPipe("gemv_q4k_fused.spv", q4k_fused_pipe_);
}
bool VulkanCompute::EnsureQ4kOprojPipeline() {
    return CreateGemvPipe("gemv_q4k_oproj.spv", q4k_oproj_pipe_);
}
bool VulkanCompute::EnsureQ4kKvaPipeline() {
    return CreateGemvPipe("gemv_q4k_kva.spv", q4k_kva_pipe_);
}
bool VulkanCompute::EnsureQ8KvaPipeline() {
    VkPipeline p = nullptr;
    return EnsureQ8KvaSxPipeline(16u, p);
}
bool VulkanCompute::EnsureQ8KvaSxPipeline(uint32_t rows, VkPipeline& out) {
    if (rows == 64u) {
        if (!CreateGemvPipe("gemv_q8_kva_sx_64.spv", q8_kva_sx64_pipe_))
            return false;
        out = q8_kva_sx64_pipe_;
        return out != nullptr;
    }
    if (rows != 16u) return false;
    if (!CreateGemvPipe("gemv_q8_kva.spv", q8_kva_pipe_)) return false;
    out = q8_kva_pipe_;
    return out != nullptr;
}
bool VulkanCompute::EnsureQ4kQkvSxPipeline(uint32_t rows, VkPipeline& out) {
    const uint32_t i = SxIdx(rows);
    if (i > 3u) return false;
    /* 64-row oproj SPV is the live shared-x binary; other row SPVs optional. */
    static const char* n[] = {"gemv_q4k_qkv_sx_32.spv", "gemv_q4k_oproj.spv",
                              "gemv_q4k_qkv_sx_128.spv",
                              "gemv_q4k_qkv_sx_256.spv"};
    if (!CreateGemvPipe(n[i], q4k_qkv_sx_pipes_[i])) return false;
    out = q4k_qkv_sx_pipes_[i];
    return out != nullptr;
}

bool VulkanCompute::DispatchGEMVFusedQ4KT(const void* packed, size_t bytes,
                                          const float* input, float* output,
                                          uint32_t rows, uint32_t cols,
                                          uint64_t pinKey) {
    const uint8_t tag = (uint8_t)(pinKey & 0xffu);
    const bool isOproj = (tag == 6u);
    const bool isQShared =
        (tag == 1u || tag == 2u) && (cols % 256u) == 0u;
    const bool isKva = (tag == 3u) && (cols % 256u) == 0u && rows > 0u;
    const bool useSharedX = isOproj || isQShared;
    const bool isQkv = (tag >= 1u && tag <= 5u);
    if (!packed || !input || !output || !bytes) return false;
    static std::atomic<uint32_t> kvaDiag{0};
    auto noteKvaFail = [&](const char* why) {
        if (tag != 3u) return;
        if (kvaDiag.fetch_add(1, std::memory_order_relaxed) >= 3u) return;
        std::printf("KVA_FUSED_MISS WHY=%s TAG=%u ROWS=%u COLS=%u "
                    "COLS_MOD256=%u IS_KVA=%d BYTES=%zu\n",
                    why, (unsigned)tag, rows, cols, cols % 256u, isKva ? 1 : 0,
                    bytes);
        std::fflush(stdout);
    };
    if (tag == 3u && !isKva) noteKvaFail("geom");

    uint32_t sxRows = 64u;
    if (isQShared) {
        const int w = rawr::live::QkvWinnerRows().load();
        if (w > 0) sxRows = (uint32_t)w;
    }
    VkPipeline pipe = nullptr;
    if (isKva) {
        if (!EnsureQ4kKvaPipeline()) {
            noteKvaFail("ensure_pipe");
            return false;
        }
        pipe = q4k_kva_pipe_;
    } else if (isQShared) {
        if (!EnsureQ4kQkvSxPipeline(sxRows, pipe)) {
            if (!EnsureQ4kOprojPipeline()) return false;
            pipe = q4k_oproj_pipe_;
            sxRows = 64u;
        }
    } else if (isOproj) {
        if (!EnsureQ4kOprojPipeline()) return false;
        pipe = q4k_oproj_pipe_;
    } else if (!EnsureQ4kFusedPipeline()) {
        return false;
    } else {
        pipe = q4k_fused_pipe_;
    }

    ++gemv_attempts_;
    const size_t inB = (size_t)cols * 4;
    const uint32_t nblk = cols >> 8;
    const uint32_t colTileBlocks = 4u;
    const uint32_t nColTiles =
        isKva ? ((nblk + colTileBlocks - 1u) / colTileBlocks) : 1u;
    const size_t outB =
        isKva ? (size_t)rows * nColTiles * 4u : (size_t)rows * 4u;
    if (!EnsureHostIo(inB, outB)) {
        if (isKva) noteKvaFail("host_io");
        return false;
    }

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
        if (!EnsurePinnedPackedWeight(packed, bytes, rows, cols, wbuf, pinKey)) {
            if (isKva) noteKvaFail("pin_weight");
            return false;
        }
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
            if (!EnsureWeightWindow(slotB, nSlots, budget)) {
                if (isKva) noteKvaFail("weight_window");
                return false;
            }
        }
        if (!StreamWeightToSlot(packed, bytes, wbuf)) {
            if (isKva) noteKvaFail("stream_slot");
            return false;
        }
    }

    if (isQShared &&
        ClimbQkvSharedXOnce(wbuf, bytes, inB, outB, rows, cols, tag, output,
                            uploadUs, pipe, sxRows, kernelUs))
        return true;

    const uint32_t rowTile =
        isKva ? 16u : (useSharedX ? (isOproj ? 64u : sxRows) : 4u);
    const uint32_t rowTiles = (rows + rowTile - 1u) / rowTile;
    const uint32_t groups = isKva ? (rowTiles * nColTiles) : rowTiles;
    const uint64_t tk0 = timeIo ? ONowUs() : 0;
    if (isKva) {
        uint32_t pc[4] = {rows, cols, nColTiles, colTileBlocks};
        if (!BindGemvStoragePc(wbuf, bytes, gemv_in_buf_, inB, gemv_out_buf_,
                               outB, pipe, pc, 4u, groups)) {
            noteKvaFail("bind_pc");
            return false;
        }
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
        if (isKva) {
            Deep2::Qkv_NoteKvaColSplit(nColTiles, groups, kernelUs);
            rawr::live::NoteKvaLiveTune(16u, true, kernelUs);
        } else if (isQShared) {
            rawr::live::NoteQkvLiveTune(rowTile, true, kernelUs);
        }
        ++q4k_fused_ops_;
        if (isQShared || isKva) ++q4k_oproj_ops_;
    } else {
        ++q4k_fused_ops_;
    }
    ++gemv_success_;
    return true;
}

bool VulkanCompute::DispatchGEMVFusedQ8Kva(const void* packed, size_t bytes,
                                           const float* input, float* output,
                                           uint32_t rows, uint32_t cols,
                                           uint64_t pinKey) {
    const uint8_t tag = (uint8_t)(pinKey & 0xffu);
    if (tag != 3u || !packed || !input || !output || !bytes || !rows)
        return false;
    if ((cols % 32u) != 0u) return false;
    if (!EnsureQ8KvaPipeline()) return false;
    ++gemv_attempts_;
    const size_t inB = (size_t)cols * 4u;
    const uint32_t nblk = (cols + 31u) / 32u;
    const uint32_t colTileBlocks = 8u; /* 256-wide shared x */
    const uint32_t nColTiles = (nblk + colTileBlocks - 1u) / colTileBlocks;
    const size_t outB = (size_t)rows * nColTiles * 4u;
    if (!EnsureHostIo(inB, outB)) return false;

    uint64_t uploadUs = 0, readbackUs = 0, kernelUs = 0;
    const bool reuseIn =
        gemv_reuse_in_next_ && gemv_in_live_cols_ == cols && gemv_in_buf_;
    gemv_reuse_in_next_ = false;
    if (reuseIn) {
        ++gemv_in_reuse_hits_;
    } else {
        const uint64_t tu0 = ONowUs();
        void* mapped = nullptr;
        vkMapMemory(device_, gemv_in_mem_, 0, inB, 0, &mapped);
        std::memcpy(mapped, input, inB);
        vkUnmapMemory(device_, gemv_in_mem_);
        gemv_in_live_cols_ = cols;
        uploadUs = ONowUs() - tu0;
    }

    VkBuffer wbuf = nullptr;
    if (WantWeightPin()) {
        if (!EnsurePinnedPackedWeight(packed, bytes, rows, cols, wbuf, pinKey))
            return false;
    } else if (!StreamWeightToSlot(packed, bytes, wbuf)) {
        return false;
    }

    uint32_t rowTile = 16u;
    const int win = rawr::live::KvaWinnerRows().load();
    if (win > 0) rowTile = (uint32_t)win;
    if (win < 0 &&
        ClimbQ8KvaOnce(wbuf, bytes, inB, outB, rows, cols, nColTiles,
                       colTileBlocks, tag, output, uploadUs, rowTile,
                       kernelUs))
        return true;

    VkPipeline pipe = nullptr;
    if (!EnsureQ8KvaSxPipeline(rowTile, pipe)) {
        if (!EnsureQ8KvaSxPipeline(16u, pipe)) return false;
        rowTile = 16u;
    }
    const uint32_t rowTiles = (rows + rowTile - 1u) / rowTile;
    const uint32_t groups = rowTiles * nColTiles;
    const uint64_t tk0 = ONowUs();
    uint32_t pc[4] = {rows, cols, nColTiles, colTileBlocks};
    if (!BindGemvStoragePc(wbuf, bytes, gemv_in_buf_, inB, gemv_out_buf_, outB,
                           pipe, pc, 4u, groups))
        return false;
    kernelUs = ONowUs() - tk0;

    const uint64_t tr0 = ONowUs();
    void* mapped = nullptr;
    vkMapMemory(device_, gemv_out_mem_, 0, outB, 0, &mapped);
    const float* part = static_cast<const float*>(mapped);
    for (uint32_t r = 0; r < rows; ++r) {
        float s = 0.f;
        for (uint32_t t = 0; t < nColTiles; ++t)
            s += part[r * nColTiles + t];
        output[r] = s;
    }
    vkUnmapMemory(device_, gemv_out_mem_);
    readbackUs = ONowUs() - tr0;

    Deep2::Qkv_NoteDispatch(tag, uploadUs, readbackUs, kernelUs,
                            (size_t)rows * 4u);
    Deep2::Qkv_NoteSharedX(tag, rows, cols, groups, kernelUs);
    Deep2::Qkv_NoteKvaColSplit(nColTiles, groups, kernelUs);
    rawr::live::NoteKvaLiveTune(rowTile, true, kernelUs);
    ++q4k_fused_ops_;
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
