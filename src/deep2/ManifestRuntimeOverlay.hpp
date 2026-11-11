#pragma once
/*
    Runtime overlay for dynamic persistent manifests.

    This stores run facts separately from discovery facts. It prevents a runtime
    failure/success from rewriting the persistent model manifest.
*/
#include <cstdint>
#include <cstdio>
#include <string>

namespace rawr::manifest_overlay {

struct RuntimeOverlay {
    std::string modelLocator;
    std::uint64_t modelFingerprint = 0;
    std::string runId;

    bool prefillObserved = false;
    bool decodeObserved = false;
    bool cleanExit = false;
    bool crashObserved = false;

    std::uint64_t tokensCommitted = 0;
    double streamerTps = 0.0;
    double forwardMs = 0.0;
    double logitsMs = 0.0;
    double sampleMs = 0.0;
    double detokMs = 0.0;
    double callbackMs = 0.0;
    double receiptMs = 0.0;

    std::string blockedAt = "NONE";
    std::string disposition = "UNOBSERVED";
};

inline void Emit(FILE* f, const RuntimeOverlay& r) noexcept {
    if (!f) return;
    std::fprintf(f, "MODEL_RUNTIME_OVERLAY_BEGIN=1\n");
    std::fprintf(f, "MODEL_LOCATION=%s\n", r.modelLocator.c_str());
    std::fprintf(f, "MODEL_FINGERPRINT=%llu RUN_ID=%s\n",
                 static_cast<unsigned long long>(r.modelFingerprint),
                 r.runId.empty() ? "none" : r.runId.c_str());
    std::fprintf(f, "PREFILL=%s DECODE=%s TOKENS_COMMITTED=%llu\n",
                 r.prefillObserved ? "OBSERVED" : "UNOBSERVED",
                 r.decodeObserved ? "OBSERVED" : "UNOBSERVED",
                 static_cast<unsigned long long>(r.tokensCommitted));
    std::fprintf(f, "STREAMER_TPS=%.6f FORWARD_MS=%.3f LOGITS_MS=%.3f SAMPLE_MS=%.3f DETOK_MS=%.3f CALLBACK_MS=%.3f RECEIPT_MS=%.3f\n",
                 r.streamerTps, r.forwardMs, r.logitsMs, r.sampleMs, r.detokMs,
                 r.callbackMs, r.receiptMs);
    std::fprintf(f, "CLEAN_EXIT=%d CRASH_OBSERVED=%d BLOCKED_AT=%s DISPOSITION=%s\n",
                 r.cleanExit ? 1 : 0,
                 r.crashObserved ? 1 : 0,
                 r.blockedAt.c_str(),
                 r.disposition.c_str());
    std::fprintf(f, "DISCOVERY_MUTATION=0 AUTHORITY_CLASS=RUNTIME_OVERLAY PROMOTE=0\n");
    std::fprintf(f, "MODEL_RUNTIME_OVERLAY_END=1\n");
    std::fflush(f);
}

} // namespace rawr::manifest_overlay
