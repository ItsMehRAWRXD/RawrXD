// QbExchangeLedger.hpp — PATH_A: name each q_b cross (not just aggregate mirror)
#pragma once
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace rawrxd::runtime {

inline std::atomic<uint64_t>& X_h2dB() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& X_d2hMirrorB() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& X_hostMemcpyB() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& X_fenceUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& X_ops() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& X_shrinkOps() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& X_fullOps() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint32_t>& X_prodHead() {
    static std::atomic<uint32_t> v{0}; return v;
}
inline std::atomic<uint32_t>& X_hostHead() {
    static std::atomic<uint32_t> v{0}; return v;
}

inline std::atomic<uint32_t>& X_nope() {
    static std::atomic<uint32_t> v{0}; return v;
}
inline std::atomic<uint32_t>& X_rope() {
    static std::atomic<uint32_t> v{0}; return v;
}

inline void QbX_Reset() noexcept {
    X_h2dB().store(0); X_d2hMirrorB().store(0); X_hostMemcpyB().store(0);
    X_fenceUs().store(0); X_ops().store(0);
    X_shrinkOps().store(0); X_fullOps().store(0);
    X_prodHead().store(0); X_hostHead().store(0);
    X_nope().store(0); X_rope().store(0);
}

inline void QbX_Note(uint64_t h2dB, uint64_t d2hB, uint64_t memcpyB,
                     uint64_t fenceUs, uint32_t prodHead, uint32_t hostHead,
                     bool shrink, uint32_t nope = 0, uint32_t rope = 0) noexcept {
    X_h2dB().fetch_add(h2dB, std::memory_order_relaxed);
    X_d2hMirrorB().fetch_add(d2hB, std::memory_order_relaxed);
    X_hostMemcpyB().fetch_add(memcpyB, std::memory_order_relaxed);
    X_fenceUs().fetch_add(fenceUs, std::memory_order_relaxed);
    X_ops().fetch_add(1, std::memory_order_relaxed);
    if (shrink) X_shrinkOps().fetch_add(1, std::memory_order_relaxed);
    else X_fullOps().fetch_add(1, std::memory_order_relaxed);
    X_prodHead().store(prodHead, std::memory_order_relaxed);
    X_hostHead().store(hostHead, std::memory_order_relaxed);
    if (nope) X_nope().store(nope, std::memory_order_relaxed);
    if (rope) X_rope().store(rope, std::memory_order_relaxed);
}

inline void QbX_Emit(FILE* f) noexcept {
    if (!f) return;
    const uint32_t ph = X_prodHead().load(), hh = X_hostHead().load();
    const uint32_t np = X_nope().load(), rp = X_rope().load();
    const uint32_t sum = np + rp;
    const char* dead = (ph && hh && hh >= ph) ? "hostHead_ge_prodHead" : "none";
    const int callerAlreadyNopeRope = (sum && hh == sum) ? 1 : 0;
    const int byteShrinkImpossible = (ph && hh && hh >= ph) ? 1 : 0;
    std::fprintf(f,
        "QB_X_OPS=%llu QB_X_SHRINK_OPS=%llu QB_X_FULL_OPS=%llu\n"
        "QB_X_H2D_HIDDEN_B=%llu\n"
        "QB_X_D2H_TO_HOST_MIRROR_B=%llu\n"
        "QB_X_HOST_MIRROR_MEMCPY_B=%llu\n"
        "QB_X_FENCE_US=%llu\n"
        "QB_X_NOPE=%u QB_X_ROPE=%u QB_X_NOPE_PLUS_ROPE=%u\n"
        "QB_X_PROD_HEAD=%u QB_X_HOST_HEAD=%u\n"
        "QB_X_CALLER_ALREADY_NOPE_ROPE=%d\n"
        "QB_X_BYTE_SHRINK_IMPOSSIBLE=%d\n"
        "QB_X_DEVICE_ATTENTION_REQUIRED_FOR_Q_B_SHRINK=%d\n"
        "QB_X_SHRINK_DEAD_REASON=%s\n"
        "QB_X_MIRROR_GAP=D2H_TO_MIRROR_WAS_WEIGHT_TAGGED|"
        "HOST_MEMCPY_NOT_IN_GPU_TRANSFER\n",
        (unsigned long long)X_ops().load(),
        (unsigned long long)X_shrinkOps().load(),
        (unsigned long long)X_fullOps().load(),
        (unsigned long long)X_h2dB().load(),
        (unsigned long long)X_d2hMirrorB().load(),
        (unsigned long long)X_hostMemcpyB().load(),
        (unsigned long long)X_fenceUs().load(),
        np, rp, sum, ph, hh, callerAlreadyNopeRope, byteShrinkImpossible,
        byteShrinkImpossible, dead);
}

} // namespace rawrxd::runtime
