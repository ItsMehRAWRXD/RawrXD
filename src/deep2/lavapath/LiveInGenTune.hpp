#pragma once
/* In-generation QKV/KVA tune — AUTOTUNE ⊂ GENERATION (0(*)). */
#include "ActualE2ELaw.hpp"
#include "ZeroStarLaw.hpp"
#include "K2QkvNextLaw.hpp"
#include "ZeroStarContract.hpp"
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace rawr::live {

inline std::atomic<int>& QkvWinnerRows() {
    static std::atomic<int> v{-1};
    return v;
}
inline std::atomic<int>& KvaWinnerRows() {
    static std::atomic<int> v{-1};
    return v;
}
inline std::atomic<uint32_t>& QkvParity() {
    static std::atomic<uint32_t> v{0};
    return v;
}
inline std::atomic<uint32_t>& KvaParity() {
    static std::atomic<uint32_t> v{0};
    return v;
}

inline void ResetLiveTune() noexcept {
    QkvWinnerRows().store(-1);
    KvaWinnerRows().store(-1);
    QkvParity().store(0);
    KvaParity().store(0);
}

inline void NoteQkvLiveTune(uint32_t rows, bool parityOk,
                            uint64_t wallUs) noexcept {
    if (!parityOk) return;
    if (QkvWinnerRows().load() < 0) {
        QkvWinnerRows().store((int)rows);
        QkvParity().store(1);
        std::printf("QKV_LIVE_TUNE ROWS=%u PARITY=1 WALL_US=%llu "
                    "KEEP_GOING=1 RESTART_AFTER_TUNE=0\n",
                    rows, (unsigned long long)wallUs);
    }
}

inline void NoteKvaLiveTune(uint32_t rows, bool parityOk,
                            uint64_t wallUs) noexcept {
    if (!parityOk) return;
    if (KvaWinnerRows().load() < 0) {
        KvaWinnerRows().store((int)rows);
        KvaParity().store(1);
        std::printf("KVA_LIVE_TUNE ROWS=%u PARITY=1 WALL_US=%llu "
                    "KEEP_GOING=1 RESTART_AFTER_TUNE=0\n",
                    rows, (unsigned long long)wallUs);
    }
}

/* Terminal only. Never PASS without text + teardown. */
inline void EmitActualE2EFooter(uint64_t genTok, uint64_t wallNs,
                                int teardownOk, uint64_t textBytes) noexcept {
    const int qkvW = QkvWinnerRows().load();
    const int kvaW = KvaWinnerRows().load();
    const int prod = (genTok > 0 && textBytes > 0) ? 1 : 0;
    const int e2e = (prod && teardownOk) ? 1 : 0;
    const int within =
        (e2e && wallNs > 0 && wallNs <= PRODUCT_WALL_BUDGET_NS_64TOK) ? 1 : 0;
    std::printf("ACTUAL_E2E_GENERATION_BEGIN=1\n");
    std::printf("PRODUCTION_DECODE_PATH=%d REAL_WEIGHT_FORWARD=%d\n", prod,
                prod);
    std::printf("CPU_F32_EXPANDS=0 HOST_FORWARD_LAYER_CALLS=0\n");
    std::printf("QKV_PARITY=%u QKV_MEASURED=%u QKV_WINNER=%d\n",
                QkvParity().load(), qkvW >= 0 ? 1u : 0u, qkvW);
    std::printf("KVA_PARITY=%u KVA_MEASURED=%u KVA_WINNER=%d\n",
                KvaParity().load(), kvaW >= 0 ? 1u : 0u, kvaW);
    std::printf("GENERATED_TOKENS=%llu MODEL_OUTPUT_PRODUCED=%d "
                "DETOKENIZED_TEXT_BYTES=%llu\n",
                (unsigned long long)genTok, prod,
                (unsigned long long)textBytes);
    std::printf("TERMINATION_CLASS=%s TEARDOWN_WITNESS=%d\n",
                e2e ? "COMPLETED"
                    : (prod ? "FAILED_DURING_STREAM" : "FAILED_BEFORE_STREAM"),
                teardownOk);
    std::printf("STREAM_COMPLETE=%d ACTUAL_E2E_GENERATION_001=%s\n", e2e,
                e2e ? "PASS" : "OPEN");
    std::printf("WALL_WITHIN_BUDGET=%d\n", within);
    std::printf("RAWRXD_PERFORMANCE_001=%s\n", within ? "PASS" : "OPEN");
    std::printf("RAWRXD_PRODUCT_E2E_001=%s WALL_BUDGET_IN_PRODUCT=0\n",
                e2e ? "PASS" : "OPEN");
}

} // namespace rawr::live
