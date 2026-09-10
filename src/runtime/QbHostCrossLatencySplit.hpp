// QbHostCrossLatencySplit — attribution of legal q_b host cross waits.
// PROMOTE=0 inventory. Does not reopen QB|KVA|LOGITS|SX|5.904.
#pragma once
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace rawrxd::runtime {

inline std::atomic<uint64_t>& XC_submitUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& XC_fenceUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& XC_invalidateUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& XC_memcpyUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& XC_attnUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& XC_ops() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& XC_attnOps() {
    static std::atomic<uint64_t> v{0}; return v;
}

inline void QbXC_Reset() noexcept {
    XC_submitUs().store(0); XC_fenceUs().store(0);
    XC_invalidateUs().store(0); XC_memcpyUs().store(0);
    XC_attnUs().store(0); XC_ops().store(0); XC_attnOps().store(0);
}

inline void QbXC_NoteCross(uint64_t submitUs, uint64_t fenceUs,
                           uint64_t invalidateUs, uint64_t memcpyUs) noexcept {
    XC_submitUs().fetch_add(submitUs, std::memory_order_relaxed);
    XC_fenceUs().fetch_add(fenceUs, std::memory_order_relaxed);
    XC_invalidateUs().fetch_add(invalidateUs, std::memory_order_relaxed);
    XC_memcpyUs().fetch_add(memcpyUs, std::memory_order_relaxed);
    XC_ops().fetch_add(1, std::memory_order_relaxed);
}

inline void QbXC_NoteAttn(uint64_t attnUs) noexcept {
    XC_attnUs().fetch_add(attnUs, std::memory_order_relaxed);
    XC_attnOps().fetch_add(1, std::memory_order_relaxed);
}

inline void QbXC_Emit(FILE* f) noexcept {
    if (!f) return;
    const uint64_t sub = XC_submitUs().load();
    const uint64_t fen = XC_fenceUs().load();
    const uint64_t inv = XC_invalidateUs().load();
    const uint64_t cpy = XC_memcpyUs().load();
    const uint64_t atn = XC_attnUs().load();
    const uint64_t ops = XC_ops().load();
    const uint64_t aops = XC_attnOps().load();
    const uint64_t lump = sub + fen + inv + cpy;
    const char* owner =
        (fen >= sub && fen >= inv && fen >= cpy) ? "FENCE_WAIT" :
        (cpy >= inv && cpy >= sub) ? "HOST_MEMCPY" :
        (inv >= sub) ? "MAP_INVALIDATE" : "SUBMIT";
    std::fprintf(f,
        "QB_CROSS_SPLIT_OPS=%llu QB_CROSS_SPLIT_ATTN_OPS=%llu\n"
        "QB_CROSS_SUBMIT_US=%llu\n"
        "QB_CROSS_FENCE_WAIT_US=%llu\n"
        "QB_CROSS_MAP_INVALIDATE_US=%llu\n"
        "QB_CROSS_HOST_MEMCPY_US=%llu\n"
        "QB_CROSS_HOST_ATTENTION_US=%llu\n"
        "QB_CROSS_LUMP_US=%llu\n"
        "QB_CROSS_FENCE_OWNER=%s\n"
        "QB_CROSS_D2H_COPY_OWNER=INSIDE_FUSED_CB_WITH_FENCE\n"
        "QB_CROSS_HOST_CONSUME_OWNER=HOST_ATTENTION\n"
        "QB_CROSS_ACTION=KEEP\n"
        "QB_CROSS_BYTES_UNCHANGED_ALLOWED=1\n",
        (unsigned long long)ops, (unsigned long long)aops,
        (unsigned long long)sub, (unsigned long long)fen,
        (unsigned long long)inv, (unsigned long long)cpy,
        (unsigned long long)atn, (unsigned long long)lump, owner);
}

} // namespace rawrxd::runtime
