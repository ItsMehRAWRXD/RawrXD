// RemovalPortfolio.hpp — bid net ms against time debt (+ confidence)
#pragma once
#include "TimeDebtAccount.hpp"
#include <algorithm>
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

struct OptimizationCost {
    uint64_t vramBytes = 0;
    uint64_t ramBytes = 0;
    double bandwidthMiBs = 0.0;
    double cpuUs = 0.0;
    double proofUs = 0.0;
    double risk = 0.0; // 0..1
};

struct PortfolioBid {
    const char* name = "";
    double grossRemovableMs = 0.0;
    double costIntroducedMs = 0.0; // patch overhead on critical path
    double confidence = 1.0;       // 0..1
    OptimizationCost cost{};
};

struct PortfolioBidResult {
    double netMs = 0.0;
    double confidenceWeightedMs = 0.0;
    double timeYieldPerGiB = 0.0; // ms / GiB VRAM (0 if free)
};

inline PortfolioBidResult EvaluateBid(const PortfolioBid& b) {
    PortfolioBidResult r;
    r.netMs = b.grossRemovableMs - b.costIntroducedMs;
    if (r.netMs < 0.0) r.netMs = 0.0;
    const double c = (std::max)(0.0, (std::min)(1.0, b.confidence));
    r.confidenceWeightedMs = r.netMs * c;
    const double gib = static_cast<double>(b.cost.vramBytes) / (1024.0 * 1024.0 * 1024.0);
    r.timeYieldPerGiB = (gib > 1e-9) ? (r.netMs / gib) : 0.0;
    return r;
}

struct PortfolioPlan {
    PortfolioBid bids[16]{};
    PortfolioBidResult results[16]{};
    int count = 0;
    double rawNetMs = 0.0;
    double confidenceNetMs = 0.0;
    double timeDebtMs = 0.0;
    double surplusMs = 0.0;
    double requiredConfidenceMs = 0.0; // e.g. 1.15 × debt
    bool rawFeasible = false;
    bool confidenceFeasible = false;
};

inline PortfolioPlan BuildPortfolio(double timeDebtMs,
                                    const PortfolioBid* bids, int n,
                                    double confidenceHeadroom = 1.15) {
    PortfolioPlan p;
    p.timeDebtMs = timeDebtMs;
    p.requiredConfidenceMs = timeDebtMs * confidenceHeadroom;
    for (int i = 0; i < n && p.count < 16; ++i) {
        p.bids[p.count] = bids[i];
        p.results[p.count] = EvaluateBid(bids[i]);
        p.rawNetMs += p.results[p.count].netMs;
        p.confidenceNetMs += p.results[p.count].confidenceWeightedMs;
        p.count++;
    }
    p.surplusMs = p.rawNetMs - timeDebtMs;
    p.rawFeasible = p.rawNetMs + 1e-9 >= timeDebtMs;
    p.confidenceFeasible = p.confidenceNetMs + 1e-9 >= p.requiredConfidenceMs;
    return p;
}

inline std::string FormatPortfolio(const PortfolioPlan& p) {
    char buf[1600];
    int n = std::snprintf(buf, sizeof(buf),
        "TIME_DEBT=%.2f  RAW=%.2f  CONF=%.2f  NEED_CONF>=%.2f\n"
        "RAW_FEASIBLE=%s  CONFIDENCE=%s\n",
        p.timeDebtMs, p.rawNetMs, p.confidenceNetMs, p.requiredConfidenceMs,
        p.rawFeasible ? "YES" : "NO",
        p.confidenceFeasible ? "PASS" : "INSUFFICIENT");
    for (int i = 0; i < p.count && n < (int)sizeof(buf) - 80; ++i) {
        n += std::snprintf(buf + n, sizeof(buf) - n,
            "  %-22s net=%5.2f conf=%5.2f yield=%.3f ms/GiB\n",
            p.bids[i].name, p.results[i].netMs,
            p.results[i].confidenceWeightedMs, p.results[i].timeYieldPerGiB);
    }
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
