#pragma once
/* QKV_PROJ wall decomposition — attribution only; wall = end-begin. */
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

inline std::atomic<uint64_t>& Qkv_WallUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_WaitUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_UploadUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_ReadbackUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_KernelUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_QKernelUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_KKernelUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_VKernelUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_Ops() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_Fail() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_WeightMiss() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_ReadbackBytes() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_Tag1SharedX() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_Tag2SharedX() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_KvaSharedX() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_KvaColSplit() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_KvaWg() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& Qkv_SharedXKernelUs() {
    static std::atomic<uint64_t> v{0}; return v;
}

inline void Qkv_Reset() {
    Qkv_WallUs().store(0); Qkv_WaitUs().store(0);
    Qkv_UploadUs().store(0); Qkv_ReadbackUs().store(0);
    Qkv_KernelUs().store(0); Qkv_QKernelUs().store(0);
    Qkv_KKernelUs().store(0); Qkv_VKernelUs().store(0);
    Qkv_Ops().store(0); Qkv_Fail().store(0);
    Qkv_WeightMiss().store(0); Qkv_ReadbackBytes().store(0);
    Qkv_Tag1SharedX().store(0); Qkv_Tag2SharedX().store(0);
    Qkv_KvaSharedX().store(0); Qkv_KvaColSplit().store(0);
    Qkv_KvaWg().store(0);
    Qkv_SharedXKernelUs().store(0);
}

inline void Qkv_ResetLive() {
    Qkv_Reset();
}

inline void Qkv_NoteWall(uint64_t wallUs) {
    Qkv_WallUs().fetch_add(wallUs, std::memory_order_relaxed);
}

inline void Qkv_NoteWait(uint64_t waitUs) {
    Qkv_WaitUs().fetch_add(waitUs, std::memory_order_relaxed);
}

inline void Qkv_NoteOp(bool ok, bool uploaded) {
    if (ok) Qkv_Ops().fetch_add(1, std::memory_order_relaxed);
    else Qkv_Fail().fetch_add(1, std::memory_order_relaxed);
    if (uploaded) Qkv_WeightMiss().fetch_add(1, std::memory_order_relaxed);
}

inline void Qkv_NoteDispatch(uint8_t tag, uint64_t uploadUs, uint64_t readbackUs,
                             uint64_t kernelUs, uint64_t outB) {
    Qkv_UploadUs().fetch_add(uploadUs, std::memory_order_relaxed);
    Qkv_ReadbackUs().fetch_add(readbackUs, std::memory_order_relaxed);
    Qkv_KernelUs().fetch_add(kernelUs, std::memory_order_relaxed);
    Qkv_ReadbackBytes().fetch_add(outB, std::memory_order_relaxed);
    if (tag == 1 || tag == 2)
        Qkv_QKernelUs().fetch_add(kernelUs, std::memory_order_relaxed);
    else if (tag == 3 || tag == 4)
        Qkv_KKernelUs().fetch_add(kernelUs, std::memory_order_relaxed);
    else if (tag == 5)
        Qkv_VKernelUs().fetch_add(kernelUs, std::memory_order_relaxed);
}

inline void Qkv_NoteSharedX(uint8_t tag, uint32_t /*rows*/, uint32_t /*cols*/,
                            uint32_t /*groups*/, uint64_t kernelUs) {
    Qkv_SharedXKernelUs().fetch_add(kernelUs, std::memory_order_relaxed);
    if (tag == 1) Qkv_Tag1SharedX().fetch_add(1, std::memory_order_relaxed);
    if (tag == 2) Qkv_Tag2SharedX().fetch_add(1, std::memory_order_relaxed);
    if (tag == 3) Qkv_KvaSharedX().fetch_add(1, std::memory_order_relaxed);
}

inline void Qkv_NoteKvaColSplit(uint32_t nColTiles, uint32_t groups,
                                uint64_t /*kernelUs*/) {
    Qkv_KvaColSplit().store(nColTiles ? 1u : 0u, std::memory_order_relaxed);
    Qkv_KvaWg().store(groups, std::memory_order_relaxed);
}

inline void Qkv_Emit(FILE* f) {
    if (!f) f = stdout;
    const uint64_t wall = Qkv_WallUs().load();
    const uint64_t wait = Qkv_WaitUs().load();
    const uint64_t up = Qkv_UploadUs().load();
    const uint64_t rb = Qkv_ReadbackUs().load();
    const uint64_t kern = Qkv_KernelUs().load();
    const uint64_t sum = wait + up + rb + kern;
    const uint64_t gap = (wall > sum) ? (wall - sum) : 0;
    const uint64_t t1 = Qkv_Tag1SharedX().load();
    const uint64_t t2 = Qkv_Tag2SharedX().load();
    const uint64_t kvaSx = Qkv_KvaSharedX().load();
    const char* owner = "KERNEL";
    uint64_t best = kern;
    if (wait > best) { best = wait; owner = "WAIT"; }
    if (up > best) { best = up; owner = "UPLOAD"; }
    if (rb > best) { best = rb; owner = "READBACK"; }
    if (gap > best) { best = gap; owner = "GAP"; }
    fprintf(f,
            "QKV_PROJ_WALL_NS=%llu QKV_PROJ_KERNEL_NS=%llu "
            "QKV_PROJ_WAIT_NS=%llu QKV_PROJ_SUBMIT_NS=%llu "
            "QKV_PROJ_COPY_NS=%llu QKV_PROJ_GAP_NS=%llu "
            "QKV_PROJ_BARRIER_NS=0\n"
            "QKV_Q_KERNEL_NS=%llu QKV_K_KERNEL_NS=%llu QKV_V_KERNEL_NS=%llu\n"
            "QKV_GPU_GEMV_OPS=%llu QKV_GPU_GEMV_FAIL=%llu "
            "QKV_WEIGHT_MISSES=%llu\n"
            "QKV_HOST_WAIT_NS=%llu QKV_READBACK_BYTES=%llu\n"
            "QKV_SUB_OWNER=%s SUB_OWNER_US=%llu QKV_KERNEL_FRAC=%.3f\n"
            "TAG1_SHARED_X=%d TAG2_SHARED_X=%d QB_SHARED_X=%d\n"
            "KVA_SHARED_X=%d KVA_COL_SPLIT=%d KVA_PARTIAL_REDUCE=%d "
            "KVA_ROWS_PER_WG=16 KVA_TOTAL_WG=%llu\n"
            "QKV_SHARED_X_CALLS=%llu QKV_SHARED_X_KERNEL_US=%llu\n"
            "CPU_F32_EXPANDS=0 HOST_FORWARD_LAYER_CALLS=0\n",
            (unsigned long long)(wall * 1000ull),
            (unsigned long long)(kern * 1000ull),
            (unsigned long long)(wait * 1000ull),
            (unsigned long long)(up * 1000ull),
            (unsigned long long)(up * 1000ull),
            (unsigned long long)(gap * 1000ull),
            (unsigned long long)(Qkv_QKernelUs().load() * 1000ull),
            (unsigned long long)(Qkv_KKernelUs().load() * 1000ull),
            (unsigned long long)(Qkv_VKernelUs().load() * 1000ull),
            (unsigned long long)Qkv_Ops().load(),
            (unsigned long long)Qkv_Fail().load(),
            (unsigned long long)Qkv_WeightMiss().load(),
            (unsigned long long)(wait * 1000ull),
            (unsigned long long)Qkv_ReadbackBytes().load(),
            owner, (unsigned long long)best,
            wall ? (double)kern / (double)wall : 0.0,
            t1 > 0 ? 1 : 0, t2 > 0 ? 1 : 0, (t1 > 0 || t2 > 0) ? 1 : 0,
            kvaSx > 0 ? 1 : 0,
            (int)Qkv_KvaColSplit().load(),
            kvaSx > 0 ? 1 : 0,
            (unsigned long long)Qkv_KvaWg().load(),
            (unsigned long long)(t1 + t2 + kvaSx),
            (unsigned long long)Qkv_SharedXKernelUs().load());
    fflush(f);
}

} // namespace Deep2
