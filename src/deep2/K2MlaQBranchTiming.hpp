// K2MlaQBranchTiming.hpp — GPU Q critical path (q_a → q_b) under SPLIT_KV.
// Component kv_a is NOT a routing signal once QKV_WALL≈max(branches).
#pragma once
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

inline std::atomic<uint64_t>& QBr_QaGpuUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& QBr_QaWaitUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& QBr_QaUploadUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& QBr_QaKernelUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& QBr_QbGpuUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& QBr_QbWaitUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& QBr_QbUploadUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& QBr_QbKernelUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& QBr_QabGapUs() {
    static std::atomic<uint64_t> v{0}; return v;
}

inline void QBr_Reset() {
    QBr_QaGpuUs().store(0); QBr_QaWaitUs().store(0);
    QBr_QaUploadUs().store(0); QBr_QaKernelUs().store(0);
    QBr_QbGpuUs().store(0); QBr_QbWaitUs().store(0);
    QBr_QbUploadUs().store(0); QBr_QbKernelUs().store(0);
    QBr_QabGapUs().store(0);
}

// tag 1=q_a, 2=q_b. uploadUs=body when weight uploaded; else kernelUs=body.
inline void QBr_NoteLane(uint8_t tag, uint64_t waitUs, uint64_t uploadUs,
                         uint64_t kernelUs) {
    const uint64_t gpu = waitUs + uploadUs + kernelUs;
    if (tag == 1) {
        QBr_QaGpuUs().fetch_add(gpu, std::memory_order_relaxed);
        QBr_QaWaitUs().fetch_add(waitUs, std::memory_order_relaxed);
        QBr_QaUploadUs().fetch_add(uploadUs, std::memory_order_relaxed);
        QBr_QaKernelUs().fetch_add(kernelUs, std::memory_order_relaxed);
    } else if (tag == 2) {
        QBr_QbGpuUs().fetch_add(gpu, std::memory_order_relaxed);
        QBr_QbWaitUs().fetch_add(waitUs, std::memory_order_relaxed);
        QBr_QbUploadUs().fetch_add(uploadUs, std::memory_order_relaxed);
        QBr_QbKernelUs().fetch_add(kernelUs, std::memory_order_relaxed);
    }
}

inline void QBr_NoteGap(uint64_t gapUs) {
    QBr_QabGapUs().fetch_add(gapUs, std::memory_order_relaxed);
}

inline void QBr_Emit(FILE* f) {
    if (!f) f = stdout;
    const uint64_t qaG = QBr_QaGpuUs().load();
    const uint64_t qaW = QBr_QaWaitUs().load();
    const uint64_t qaU = QBr_QaUploadUs().load();
    const uint64_t qaK = QBr_QaKernelUs().load();
    const uint64_t qbG = QBr_QbGpuUs().load();
    const uint64_t qbW = QBr_QbWaitUs().load();
    const uint64_t qbU = QBr_QbUploadUs().load();
    const uint64_t qbK = QBr_QbKernelUs().load();
    const uint64_t gap = QBr_QabGapUs().load();
    const uint64_t branch = qaG + qbG + gap;
    const char* sub = "q_a";
    uint64_t best = qaK ? qaK : qaG;
    if ((qbK ? qbK : qbG) > best) { best = qbK ? qbK : qbG; sub = "q_b"; }
    if (gap > best) { best = gap; sub = "gap"; }
    if (qaU + qbU > best) { best = qaU + qbU; sub = "upload"; }
    fprintf(f,
            "Q_A_GPU_US=%llu Q_A_WAIT_US=%llu Q_A_UPLOAD_US=%llu "
            "Q_A_KERNEL_US=%llu\n"
            "Q_B_GPU_US=%llu Q_B_WAIT_US=%llu Q_B_UPLOAD_US=%llu "
            "Q_B_KERNEL_US=%llu\n"
            "Q_AB_GAP_US=%llu Q_BRANCH_PROBE_US=%llu\n"
            "MLA_Q_CRITICAL_OWNER=%s SUB_OWNER_US=%llu\n",
            (unsigned long long)qaG, (unsigned long long)qaW,
            (unsigned long long)qaU, (unsigned long long)qaK,
            (unsigned long long)qbG, (unsigned long long)qbW,
            (unsigned long long)qbU, (unsigned long long)qbK,
            (unsigned long long)gap, (unsigned long long)branch,
            sub, (unsigned long long)best);
    fflush(f);
}

} // namespace Deep2
