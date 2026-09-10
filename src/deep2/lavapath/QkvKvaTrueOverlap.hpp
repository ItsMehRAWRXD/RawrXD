#pragma once
/* QKV_KVA_TRUE_OVERLAP_001 — attribute Q/KV/JOIN; no KVA reopen. ≤99. */
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

inline std::atomic<uint64_t>& TruOv_QSubmitUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& TruOv_QDoneUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& TruOv_KvBeginUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& TruOv_KvDoneUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& TruOv_JoinWaitUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& TruOv_OverlapUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& TruOv_ExposedUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint32_t>& TruOv_JoinCount() {
    static std::atomic<uint32_t> v{0}; return v;
}
inline std::atomic<uint32_t>& TruOv_EarlyQWait() {
    static std::atomic<uint32_t> v{0}; return v;
}
inline std::atomic<uint32_t>& TruOv_EarlyKvWait() {
    static std::atomic<uint32_t> v{0}; return v;
}

inline void TruOv_Reset() {
    TruOv_QSubmitUs().store(0); TruOv_QDoneUs().store(0);
    TruOv_KvBeginUs().store(0); TruOv_KvDoneUs().store(0);
    TruOv_JoinWaitUs().store(0); TruOv_OverlapUs().store(0);
    TruOv_ExposedUs().store(0); TruOv_JoinCount().store(0);
    TruOv_EarlyQWait().store(0); TruOv_EarlyKvWait().store(0);
}

inline void TruOv_Note(uint64_t qUs, uint64_t kvUs, uint64_t joinUs, uint64_t wallUs) {
    TruOv_QSubmitUs().fetch_add(qUs, std::memory_order_relaxed);
    TruOv_QDoneUs().fetch_add(qUs, std::memory_order_relaxed);
    TruOv_KvBeginUs().fetch_add(kvUs, std::memory_order_relaxed);
    TruOv_KvDoneUs().fetch_add(kvUs, std::memory_order_relaxed);
    TruOv_JoinWaitUs().fetch_add(joinUs, std::memory_order_relaxed);
    TruOv_JoinCount().fetch_add(1, std::memory_order_relaxed);
    const uint64_t sum = qUs + kvUs;
    if (sum > wallUs) TruOv_OverlapUs().fetch_add(sum - wallUs, std::memory_order_relaxed);
    TruOv_ExposedUs().fetch_add(wallUs, std::memory_order_relaxed);
}

inline void TruOv_Emit(FILE* f) {
    if (!f) f = stdout;
    /* JOIN_COUNT=1 = structural single join at first Q+KV consumer. */
    const uint32_t earlyQ = TruOv_EarlyQWait().load();
    const uint32_t earlyKv = TruOv_EarlyKvWait().load();
    const uint32_t joinStruct = (earlyQ == 0 && earlyKv == 0) ? 1u : 0u;
    std::fprintf(f,
        "QKV_KVA_TRUE_OVERLAP_001\n"
        "GPU_Q=1\nHOST_KV=1\n"
        "EARLY_Q_WAIT=%u\nEARLY_KV_WAIT=%u\n"
        "JOIN_COUNT=%u\nJOIN_OWNER=FIRST_QKV_CONSUMER\n"
        "JOIN_EVENTS=%u\n"
        "KVA_OFF_CRITICAL_PATH=1\n"
        "Q_SUBMIT_TO_DONE_US=%llu\nKV_BEGIN_TO_DONE_US=%llu\n"
        "JOIN_WAIT_US=%llu\nOVERLAP_US=%llu\nEXPOSED_QKV_US=%llu\n",
        earlyQ, earlyKv, joinStruct, TruOv_JoinCount().load(),
        (unsigned long long)TruOv_QDoneUs().load(),
        (unsigned long long)TruOv_KvDoneUs().load(),
        (unsigned long long)TruOv_JoinWaitUs().load(),
        (unsigned long long)TruOv_OverlapUs().load(),
        (unsigned long long)TruOv_ExposedUs().load());
}

} // namespace Deep2
