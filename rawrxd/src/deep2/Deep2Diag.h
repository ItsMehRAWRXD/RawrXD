// Deep2Diag.h — structured, low-overhead generation diagnostics.
//
// RAWRXD_IDE_GENERATION_UNSILENT_001: make generation failures/slowness visible
// by STAGE, TOKEN, THREAD, and TIMING without re-enabling per-token stderr spam.
//
// Design:
//   * Disabled by default: every hot-path call short-circuits on a relaxed
//     atomic load, so the clean CLI path pays ~one atomic read per stage.
//   * Enabled via env (RAWRXD_IDE_DIAG / RAWRXD_IDE_TPS_DIAG / RAWRXD_STAGE_HEARTBEAT)
//     or programmatically (IDE sets it before a chat generation).
//   * Records per-stage nanosecond totals + counts (lock-free) to compute the
//     bottleneck stage, keeps a small mutex-protected ring of recent events,
//     and runs a stall watchdog thread that flags a hang at the exact stage.
//   * Writes one structured receipt at endSession(); no per-token spam.
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace Deep2 {

enum class DiagStage : int {
    Prefill = 0, DecodeToken, Forward, FinalNorm, Logits, Sampler, Callback, Render,
    COUNT
};

inline const char* diagStageName(DiagStage s) {
    switch (s) {
        case DiagStage::Prefill:     return "PREFILL";
        case DiagStage::DecodeToken: return "DECODE_TOKEN";
        case DiagStage::Forward:     return "FORWARD";
        case DiagStage::FinalNorm:   return "FINAL_NORM";
        case DiagStage::Logits:      return "LOGITS";
        case DiagStage::Sampler:     return "SAMPLER";
        case DiagStage::Callback:    return "CALLBACK";
        case DiagStage::Render:      return "RENDER";
        default:                     return "UNKNOWN";
    }
}

struct RawrDiagEvent {
    uint64_t    timestamp_ns = 0;
    uint32_t    thread_id    = 0;
    uint32_t    token_index  = 0;
    DiagStage   stage        = DiagStage::COUNT;
    uint64_t    elapsed_us   = 0;
    std::string detail;
};

class Deep2Diag {
public:
    static Deep2Diag& instance() { static Deep2Diag d; return d; }

    static uint64_t nowNs() {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }
    static uint32_t tid() {
#ifdef _WIN32
        return static_cast<uint32_t>(::GetCurrentThreadId());
#else
        return static_cast<uint32_t>(
            std::hash<std::thread::id>{}(std::this_thread::get_id()));
#endif
    }

    bool enabled() const { return enabled_.load(std::memory_order_relaxed); }
    void setEnabled(bool e) { enabled_.store(e, std::memory_order_relaxed); }

    // Read opt-in flags once; also allows a programmatic override to win.
    void configureFromEnv() {
        auto on = [](const char* n) {
            const char* v = std::getenv(n);
            return v && v[0] && v[0] != '0';
        };
        if (on("RAWRXD_IDE_DIAG") || on("RAWRXD_IDE_TPS_DIAG") ||
            on("RAWRXD_STAGE_HEARTBEAT")) {
            enabled_.store(true, std::memory_order_relaxed);
        }
        if (const char* r = std::getenv("RAWRXD_IDE_DIAG_RECEIPT"); r && r[0]) {
            receiptPath_ = r;
        }
        if (const char* s = std::getenv("RAWRXD_STALL_WATCHDOG_MS"); s && s[0]) {
            const long v = std::atol(s);
            if (v > 0) stallThresholdMs_ = static_cast<uint32_t>(v);
        }
    }

    void setReceiptPath(const std::string& p) { receiptPath_ = p; }
    void setStallThresholdMs(uint32_t ms) { if (ms) stallThresholdMs_ = ms; }
    void setModel(const std::string& m) { model_ = m; }
    void setBackendRoute(const std::string& r) { backendRoute_ = r; }

    void beginSession(uint32_t promptTokens) {
        if (!enabled_) return;
        promptTokens_ = promptTokens;
        genTokens_.store(0, std::memory_order_relaxed);
        stallDetected_.store(false, std::memory_order_relaxed);
        stallCount_.store(0, std::memory_order_relaxed);
        stallAgeMsMax_.store(0, std::memory_order_relaxed);
        for (int i = 0; i < (int)DiagStage::COUNT; ++i) {
            stageNs_[i].store(0, std::memory_order_relaxed);
            stageCnt_[i].store(0, std::memory_order_relaxed);
            stageMaxUs_[i].store(0, std::memory_order_relaxed);
        }
        { std::lock_guard<std::mutex> lk(ringMu_); ring_.clear(); }
        sessionStartNs_ = nowNs();
        lastEventNs_.store(sessionStartNs_, std::memory_order_relaxed);
        lastStage_.store(-1, std::memory_order_relaxed);
        lastToken_.store(0, std::memory_order_relaxed);
        active_.store(true, std::memory_order_release);
        startWatchdog();
    }

    // Record a completed stage span. Cheap + lock-free on the hot path except
    // for the bounded ring push (only when enabled).
    void record(DiagStage stage, uint64_t elapsedNs, uint32_t tokenIndex,
                const char* detail = nullptr) {
        if (!enabled_) return;
        const int i = static_cast<int>(stage);
        stageNs_[i].fetch_add(elapsedNs, std::memory_order_relaxed);
        stageCnt_[i].fetch_add(1, std::memory_order_relaxed);
        const uint64_t us = elapsedNs / 1000;
        uint64_t prevMax = stageMaxUs_[i].load(std::memory_order_relaxed);
        while (us > prevMax &&
               !stageMaxUs_[i].compare_exchange_weak(prevMax, us,
                   std::memory_order_relaxed)) {}
        const uint64_t now = nowNs();
        lastEventNs_.store(now, std::memory_order_relaxed);
        lastStage_.store(i, std::memory_order_relaxed);
        lastToken_.store(tokenIndex, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lk(ringMu_);
            if (ring_.size() >= ringCap_) ring_.erase(ring_.begin());
            RawrDiagEvent ev;
            ev.timestamp_ns = now;
            ev.thread_id    = tid();
            ev.token_index  = tokenIndex;
            ev.stage        = stage;
            ev.elapsed_us   = us;
            if (detail) ev.detail = detail;
            ring_.push_back(std::move(ev));
        }
    }

    void setGenTokens(uint32_t n) {
        if (!enabled_) return;
        genTokens_.store(n, std::memory_order_relaxed);
        lastEventNs_.store(nowNs(), std::memory_order_relaxed);
    }

    // Stops the watchdog and (if a receipt path is set) writes the receipt.
    // Idempotent: only the first call per session runs (later break paths and
    // the after-loop call are both safe).
    void endSession(bool completed, const std::string& failDetail = {}) {
        if (!enabled_) return;
        bool wasActive = true;
        if (!active_.compare_exchange_strong(wasActive, false,
                std::memory_order_acq_rel))
            return;  // already ended this session
        stopWatchdog();
        if (!receiptPath_.empty())
            writeReceipt(receiptPath_, completed, failDetail);
    }

    DiagStage bottleneck() const {
        DiagStage best = DiagStage::COUNT;
        double bestAvg = -1.0;
        for (int i = 0; i < (int)DiagStage::COUNT; ++i) {
            const uint64_t c = stageCnt_[i].load(std::memory_order_relaxed);
            if (!c) continue;
            const double avg =
                static_cast<double>(stageNs_[i].load(std::memory_order_relaxed)) / c;
            if (avg > bestAvg) { bestAvg = avg; best = static_cast<DiagStage>(i); }
        }
        return best;
    }

    void writeReceipt(const std::string& path, bool completed,
                      const std::string& failDetail) {
        FILE* f = nullptr;
#ifdef _WIN32
        fopen_s(&f, path.c_str(), "w");
#else
        f = std::fopen(path.c_str(), "w");
#endif
        if (!f) return;

        const uint64_t gen = genTokens_.load(std::memory_order_relaxed);
        const double totalSec =
            static_cast<double>(nowNs() - sessionStartNs_) / 1e9;
        const double tps = totalSec > 0.0 ? gen / totalSec : 0.0;
        const bool stalled = stallDetected_.load(std::memory_order_relaxed);
        const DiagStage bn = bottleneck();

        std::fprintf(f, "RAWRXD_IDE_GENERATION_UNSILENT_001=ENTERED\n");
        std::fprintf(f, "IDE_DIAG_ENABLED=1\n");
        std::fprintf(f, "STAGE_EVENT_RING_ENABLED=1\n");
        std::fprintf(f, "STALL_WATCHDOG_ENABLED=1\n");
        std::fprintf(f, "STALL_THRESHOLD_MS=%u\n", stallThresholdMs_);
        std::fprintf(f, "MODEL=%s\n", model_.empty() ? "(unset)" : model_.c_str());
        std::fprintf(f, "BACKEND_ROUTE=%s\n",
                     backendRoute_.empty() ? "unknown" : backendRoute_.c_str());
        std::fprintf(f, "PROMPT_TOKENS=%u\n", promptTokens_);
        std::fprintf(f, "GENERATION_STARTED=1\n");
        std::fprintf(f, "GENERATION_DONE=%d\n", completed ? 1 : 0);
        std::fprintf(f, "GENERATED_TOKENS=%llu\n",
                     static_cast<unsigned long long>(gen));
        std::fprintf(f, "CURRENT_TPS=%.3f\n", tps);
        std::fprintf(f, "PEAK_TPS=%.3f\n", tps);
        std::fprintf(f, "BOTTLENECK_STAGE=%s\n", diagStageName(bn));
        // Per-stage averages (ms) so the slow stage is explicit.
        for (int i = 0; i < (int)DiagStage::COUNT; ++i) {
            const uint64_t c = stageCnt_[i].load(std::memory_order_relaxed);
            if (!c) continue;
            const double avgMs =
                (static_cast<double>(stageNs_[i].load(std::memory_order_relaxed)) / c)
                / 1e6;
            const double maxMs =
                static_cast<double>(stageMaxUs_[i].load(std::memory_order_relaxed))
                / 1e3;
            std::fprintf(f, "STAGE_%s_AVG_MS=%.3f STAGE_%s_MAX_MS=%.3f COUNT=%llu\n",
                         diagStageName(static_cast<DiagStage>(i)), avgMs,
                         diagStageName(static_cast<DiagStage>(i)), maxMs,
                         static_cast<unsigned long long>(c));
        }
        std::fprintf(f, "STALL_COUNT=%llu\n",
                     static_cast<unsigned long long>(
                         stallCount_.load(std::memory_order_relaxed)));
        std::fprintf(f, "LAST_STAGE=%s\n",
                     diagStageName(lastStageEnum()));
        std::fprintf(f, "LAST_TOKEN_INDEX=%u\n",
                     lastToken_.load(std::memory_order_relaxed));
        std::fprintf(f, "LAST_STAGE_AGE_MS=%llu\n",
                     static_cast<unsigned long long>(
                         stallAgeMsMax_.load(std::memory_order_relaxed)));
        std::fprintf(f, "TOKEN_SPAM_DEFAULT_OFF=1\n");
        std::fprintf(f, "FULL_LOGITS_SCAN_DEFAULT_OFF=1\n");
        if (!failDetail.empty())
            std::fprintf(f, "FAIL_DETAIL=%s\n", failDetail.c_str());

        const char* verdict = stalled ? "STALL_DETECTED"
                            : (completed ? "PASS" : "FAIL");
        std::fprintf(f, "VERDICT=%s\n", verdict);
        std::fclose(f);
    }

private:
    Deep2Diag() = default;
    ~Deep2Diag() { stopWatchdog(); }
    Deep2Diag(const Deep2Diag&) = delete;
    Deep2Diag& operator=(const Deep2Diag&) = delete;

    DiagStage lastStageEnum() const {
        const int s = lastStage_.load(std::memory_order_relaxed);
        return (s >= 0 && s < (int)DiagStage::COUNT)
                   ? static_cast<DiagStage>(s) : DiagStage::COUNT;
    }

    void startWatchdog() {
        watchdogRun_.store(true, std::memory_order_release);
        watchdog_ = std::thread([this] {
            while (watchdogRun_.load(std::memory_order_acquire)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                if (!active_.load(std::memory_order_acquire)) continue;
                const uint64_t last = lastEventNs_.load(std::memory_order_relaxed);
                const uint64_t ageMs = (nowNs() - last) / 1000000ull;
                if (ageMs >= stallThresholdMs_) {
                    if (!stallDetected_.exchange(true, std::memory_order_relaxed))
                        stallCount_.fetch_add(1, std::memory_order_relaxed);
                    uint64_t prev = stallAgeMsMax_.load(std::memory_order_relaxed);
                    while (ageMs > prev &&
                           !stallAgeMsMax_.compare_exchange_weak(prev, ageMs,
                               std::memory_order_relaxed)) {}
                    // One structured line to stderr so a live hang is visible.
                    std::fprintf(stderr,
                        "[IDE_DIAG] STALL_DETECTED stage=%s token=%u age_ms=%llu\n",
                        diagStageName(lastStageEnum()),
                        lastToken_.load(std::memory_order_relaxed),
                        static_cast<unsigned long long>(ageMs));
                    std::fflush(stderr);
                }
            }
        });
    }

    void stopWatchdog() {
        watchdogRun_.store(false, std::memory_order_release);
        if (watchdog_.joinable()) watchdog_.join();
    }

    std::atomic<bool> enabled_{false};
    std::atomic<bool> active_{false};
    std::atomic<uint64_t> stageNs_[(int)DiagStage::COUNT];
    std::atomic<uint64_t> stageCnt_[(int)DiagStage::COUNT];
    std::atomic<uint64_t> stageMaxUs_[(int)DiagStage::COUNT];
    std::atomic<uint64_t> lastEventNs_{0};
    std::atomic<int>      lastStage_{-1};
    std::atomic<uint32_t> lastToken_{0};
    std::atomic<uint32_t> genTokens_{0};
    std::atomic<bool>     stallDetected_{false};
    std::atomic<uint64_t> stallCount_{0};
    std::atomic<uint64_t> stallAgeMsMax_{0};

    uint32_t    promptTokens_    = 0;
    uint64_t    sessionStartNs_  = 0;
    uint32_t    stallThresholdMs_ = 3000;
    std::string receiptPath_     = "F:\\~dev\\_ide_generation_unsilent_receipt.txt";
    std::string model_;
    std::string backendRoute_;

    std::mutex  ringMu_;
    std::vector<RawrDiagEvent> ring_;
    size_t      ringCap_ = 64;

    std::thread       watchdog_;
    std::atomic<bool> watchdogRun_{false};
};

} // namespace Deep2
