// StreamLinkBudget.hpp — physical link-budget witness for streamed weights
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstdint>

namespace Deep2 {

inline double StreamLinkBudget_Env(const char* name, double fallback) noexcept {
#ifdef _WIN32
    char* value = nullptr;
    size_t length = 0;
    if (_dupenv_s(&value, &length, name) == 0 && value) {
        const double parsed = std::atof(value);
        std::free(value);
        return parsed > 0.0 ? parsed : fallback;
    }
    return fallback;
#else
    if (const char* value = std::getenv(name)) {
        const double parsed = std::atof(value);
        return parsed > 0.0 ? parsed : fallback;
    }
    return fallback;
#endif
}

inline double StreamLinkBudget_BandwidthBps() noexcept {
    // PCIe 5 x16 practical planning value. This is a budget, not a measured
    // device result; the receipt remains NOT_RUN until transfer counters exist.
    return StreamLinkBudget_Env("DEEP2_STREAM_LINK_BW_BPS", 54.0e9);
}

inline double StreamLinkBudget_TargetTps() noexcept {
    return StreamLinkBudget_Env("DEEP2_STREAM_TARGET_TPS", 150.0);
}

inline double StreamLinkBudget_BytesPerToken() noexcept {
    const double bw = StreamLinkBudget_BandwidthBps();
    const double tps = StreamLinkBudget_TargetTps();
    return (bw > 0.0 && tps > 0.0) ? bw / tps : 0.0;
}

inline double StreamLinkBudget_MeasuredBytesPerToken(uint64_t bytesToGpu,
                                                      uint64_t tokens) noexcept {
    return tokens ? static_cast<double>(bytesToGpu) / static_cast<double>(tokens)
                  : 0.0;
}

inline double StreamLinkBudget_TpsCeiling(uint64_t bytesToGpu,
                                           uint64_t tokens) noexcept {
    const double bpt = StreamLinkBudget_MeasuredBytesPerToken(bytesToGpu, tokens);
    return bpt > 0.0 ? StreamLinkBudget_BandwidthBps() / bpt : 0.0;
}

inline const char* StreamLinkBudget_Status(uint64_t bytesToGpu,
                                           uint64_t tokens) noexcept {
    if (!tokens) return "NOT_RUN";
    return StreamLinkBudget_MeasuredBytesPerToken(bytesToGpu, tokens) <=
                   StreamLinkBudget_BytesPerToken()
               ? "PASS"
               : "FAIL";
}

inline void StreamLinkBudget_Emit(FILE* f, uint64_t bytesToGpu,
                                  uint64_t tokens) noexcept {
    if (!f) f = stdout;
    std::fprintf(f, "STREAM_LINK_BW_BPS=%.0f\n", StreamLinkBudget_BandwidthBps());
    std::fprintf(f, "STREAM_LINK_TARGET_TPS=%.3f\n", StreamLinkBudget_TargetTps());
    std::fprintf(f, "STREAM_LINK_BUDGET_BPT=%.1f\n",
                 StreamLinkBudget_BytesPerToken());
    std::fprintf(f, "STREAM_LINK_MEASURED_BPT=%.1f\n",
                 StreamLinkBudget_MeasuredBytesPerToken(bytesToGpu, tokens));
    std::fprintf(f, "STREAM_LINK_TPS_CEILING=%.3f\n",
                 StreamLinkBudget_TpsCeiling(bytesToGpu, tokens));
    std::fprintf(f, "STREAM_LINK_BUDGET_STATUS=%s\n",
                 StreamLinkBudget_Status(bytesToGpu, tokens));
}

} // namespace Deep2
