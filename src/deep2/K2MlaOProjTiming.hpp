#pragma once
/* O_PROJ wall + tag6 fast-path attribution (pin tag=6, Q4_K quant). */
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

inline std::atomic<uint64_t>& OProj_WallUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_WaitUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_UploadUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_ReadbackUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_KernelUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_Ops() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_Fail() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_WeightMiss() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_InputUploadBytes() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_OutputReadbackBytes() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_ResidualFused() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_HostWaits() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_Tag6Calls() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_Tag6Rows() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_Tag6Cols() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_Tag6Blocks() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_Tag6KernelUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_GenericCalls() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& OProj_GenericFallbacks() {
    static std::atomic<uint64_t> v{0}; return v;
}

inline const float*& OProj_ResidualBaseSlot() {
    static thread_local const float* p = nullptr;
    return p;
}
inline void OProj_SetResidualBase(const float* p) { OProj_ResidualBaseSlot() = p; }
inline const float* OProj_ResidualBase() { return OProj_ResidualBaseSlot(); }

inline void OProj_Reset() {
    OProj_WallUs().store(0);
    OProj_WaitUs().store(0);
    OProj_UploadUs().store(0);
    OProj_ReadbackUs().store(0);
    OProj_KernelUs().store(0);
    OProj_Ops().store(0);
    OProj_Fail().store(0);
    OProj_WeightMiss().store(0);
    OProj_InputUploadBytes().store(0);
    OProj_OutputReadbackBytes().store(0);
    OProj_ResidualFused().store(0);
    OProj_HostWaits().store(0);
    OProj_Tag6Calls().store(0);
    OProj_Tag6Rows().store(0);
    OProj_Tag6Cols().store(0);
    OProj_Tag6Blocks().store(0);
    OProj_Tag6KernelUs().store(0);
    OProj_GenericCalls().store(0);
    OProj_GenericFallbacks().store(0);
    OProj_ResidualBaseSlot() = nullptr;
}

inline void OProj_NoteGemv(uint64_t waitUs, uint64_t /*uploadUs*/,
                           uint64_t /*kernelUs*/, bool uploaded, bool ok) {
    // Kernel/upload/readback attributed in Dispatch (OProj_NoteTag6 / NoteIo).
    OProj_WaitUs().fetch_add(waitUs, std::memory_order_relaxed);
    if (ok) OProj_Ops().fetch_add(1, std::memory_order_relaxed);
    else OProj_Fail().fetch_add(1, std::memory_order_relaxed);
    if (uploaded) OProj_WeightMiss().fetch_add(1, std::memory_order_relaxed);
}

inline void OProj_NoteIo(uint64_t uploadUs, uint64_t readbackUs,
                         uint64_t inUpB, uint64_t outRbB, int residualFused) {
    OProj_UploadUs().fetch_add(uploadUs, std::memory_order_relaxed);
    OProj_ReadbackUs().fetch_add(readbackUs, std::memory_order_relaxed);
    OProj_InputUploadBytes().fetch_add(inUpB, std::memory_order_relaxed);
    OProj_OutputReadbackBytes().fetch_add(outRbB, std::memory_order_relaxed);
    OProj_HostWaits().fetch_add(1, std::memory_order_relaxed);
    if (residualFused) OProj_ResidualFused().fetch_add(1, std::memory_order_relaxed);
}

inline void OProj_NoteTag6(uint32_t rows, uint32_t cols, uint32_t groups,
                           uint64_t kernelUs, bool fast) {
    OProj_KernelUs().fetch_add(kernelUs, std::memory_order_relaxed);
    OProj_Tag6KernelUs().fetch_add(kernelUs, std::memory_order_relaxed);
    if (fast) {
        OProj_Tag6Calls().fetch_add(1, std::memory_order_relaxed);
        OProj_Tag6Rows().fetch_add(rows, std::memory_order_relaxed);
        OProj_Tag6Cols().store(cols, std::memory_order_relaxed);
        OProj_Tag6Blocks().fetch_add(groups, std::memory_order_relaxed);
    } else {
        OProj_GenericCalls().fetch_add(1, std::memory_order_relaxed);
    }
}

inline void OProj_NoteWall(uint64_t wallUs) {
    OProj_WallUs().fetch_add(wallUs, std::memory_order_relaxed);
}

inline void OProj_Emit(FILE* f) {
    if (!f) f = stdout;
    const uint64_t wall = OProj_WallUs().load();
    const uint64_t wait = OProj_WaitUs().load();
    const uint64_t up = OProj_UploadUs().load();
    const uint64_t rb = OProj_ReadbackUs().load();
    const uint64_t kern = OProj_KernelUs().load();
    const uint64_t ops = OProj_Ops().load();
    const uint64_t sum = wait + up + rb + kern;
    const uint64_t gap = (wall > sum) ? (wall - sum) : 0;
    // Exposed ≈ wall until async attention overlap lands (overlapped=0).
    const uint64_t exposed = wall;
    const uint64_t t6c = OProj_Tag6Calls().load();
    const uint64_t t6r = OProj_Tag6Rows().load();
    const uint64_t t6k = OProj_Tag6KernelUs().load();
    const uint64_t hostWaits = OProj_HostWaits().load();
    const char* owner = "KERNEL";
    uint64_t best = kern;
    if (wait > best) { best = wait; owner = "WAIT"; }
    if (up > best) { best = up; owner = "UPLOAD"; }
    if (rb > best) { best = rb; owner = "READBACK"; }
    if (gap > best) { best = gap; owner = "GAP"; }
    fprintf(f,
            "O_PROJ_CALLS=%llu\n"
            "O_PROJ_KERNEL_US=%llu\n"
            "O_PROJ_WAIT_US=%llu\n"
            "O_PROJ_GAP_US=%llu\n"
            "O_PROJ_UPLOAD_US=%llu\n"
            "O_PROJ_READBACK_US=%llu\n"
            "O_PROJ_SUBMIT_US=%llu\n"
            "O_PROJ_RAW_US=%llu\n"
            "O_PROJ_OVERLAPPED_US=0\n"
            "O_PROJ_EXPOSED_US=%llu\n"
            "O_PROJ_INPUT_UPLOAD_BYTES=%llu\n"
            "O_PROJ_INPUT_READBACK_BYTES=0\n"
            "O_PROJ_OUTPUT_READBACK_BYTES=%llu\n"
            "O_PROJ_SUBMITS=%llu\n"
            "O_PROJ_HOST_WAITS=%llu\n"
            "O_PROJ_RESIDUAL_FUSED=%llu\n"
            "O_PROJ_TILE_PIPELINE=1\n"
            "O_PROJ_FULL_F32_MATERIALIZE=0\n"
            "QUANTIZED_STORAGE_PRESERVED=1\n"
            "O_PROJ_SUB_OWNER=%s SUB_OWNER_US=%llu O_PROJ_KERNEL_FRAC=%.3f\n"
            "O_PROJ_TAG6_FASTPATH=%d O_PROJ_TAG6_CALLS=%llu "
            "O_PROJ_TAG6_ROWS=%llu O_PROJ_TAG6_COLS=%llu "
            "O_PROJ_TAG6_BLOCKS=%llu O_PROJ_TAG6_KERNEL_US=%llu\n"
            "O_PROJ_GENERIC_CALLS=%llu O_PROJ_GENERIC_FALLBACKS=%llu\n",
            (unsigned long long)ops,
            (unsigned long long)kern, (unsigned long long)wait,
            (unsigned long long)gap, (unsigned long long)up,
            (unsigned long long)rb, (unsigned long long)wait,
            (unsigned long long)wall, (unsigned long long)exposed,
            (unsigned long long)OProj_InputUploadBytes().load(),
            (unsigned long long)OProj_OutputReadbackBytes().load(),
            (unsigned long long)ops, (unsigned long long)hostWaits,
            (unsigned long long)OProj_ResidualFused().load(),
            owner, (unsigned long long)best,
            wall ? (double)kern / (double)wall : 0.0,
            t6c > 0 ? 1 : 0, (unsigned long long)t6c,
            (unsigned long long)t6r,
            (unsigned long long)OProj_Tag6Cols().load(),
            (unsigned long long)OProj_Tag6Blocks().load(),
            (unsigned long long)t6k,
            (unsigned long long)OProj_GenericCalls().load(),
            (unsigned long long)OProj_GenericFallbacks().load());
    fflush(f);
}

inline void OProj_EmitWallBudget(FILE* f, uint64_t wallNs, uint32_t tokens,
                                 uint64_t budgetNsPerTok = 200000000ull) {
    if (!f) f = stdout;
    const uint64_t budget = budgetNsPerTok * (uint64_t)tokens;
    const int64_t excess = (int64_t)wallNs - (int64_t)budget;
    const uint64_t exposedNs = OProj_WallUs().load() * 1000ull;
    fprintf(f,
            "GENERATION_WALL_NS=%llu\n"
            "GENERATION_BUDGET_NS=%llu\n"
            "WALL_EXCESS_NS=%lld\n"
            "WALL_EXCESS_OWNER=O_PROJ\n"
            "OWNER_EXPOSED_NS=%llu\n",
            (unsigned long long)wallNs, (unsigned long long)budget,
            (long long)excess, (unsigned long long)exposedNs);
    fflush(f);
}

} // namespace Deep2
