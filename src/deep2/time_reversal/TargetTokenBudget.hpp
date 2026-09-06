// TargetTokenBudget.hpp — allocate allowed ms across subsystems
#pragma once
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

struct TargetTokenBudget {
    double attentionMs = 0.0;
    double ffnMs = 0.0;
    double logitsMs = 0.0;
    double kvMs = 0.0;
    double weightMovementMs = 0.0;
    double syncMs = 0.0;
    double schedulerMs = 0.0;
    double verificationMs = 0.0;
    double reserveMs = 0.0;

    double total() const {
        return attentionMs + ffnMs + logitsMs + kvMs + weightMovementMs +
               syncMs + schedulerMs + verificationMs + reserveMs;
    }
};

struct BudgetVariance {
    const char* name = "";
    double budgetMs = 0.0;
    double actualMs = 0.0;
    double varianceMs = 0.0; // actual - budget; >0 BAD
    bool bad = false;
};

inline TargetTokenBudget DefaultBudgetForTarget(double targetMs) {
    // Proportional skeleton for 20 ms baseline; scale to target
    const double s = targetMs / 20.0;
    TargetTokenBudget b;
    b.attentionMs = 4.80 * s;
    b.ffnMs = 6.50 * s;
    b.logitsMs = 1.20 * s;
    b.kvMs = 1.20 * s;
    b.weightMovementMs = 1.50 * s;
    b.syncMs = 0.80 * s;
    b.schedulerMs = 0.50 * s;
    b.verificationMs = 0.70 * s;
    b.reserveMs = 2.80 * s;
    return b;
}

inline void FillVariance(BudgetVariance* out, int& n, const char* name,
                         double budget, double actual) {
    out[n] = {name, budget, actual, actual - budget, actual > budget + 1e-9};
    ++n;
}

inline std::string FormatBudgetVariance(const TargetTokenBudget& b,
                                        double attn, double ffn, double logits,
                                        double kv, double weights, double sync,
                                        double sched, double ver) {
    BudgetVariance v[8];
    int n = 0;
    FillVariance(v, n, "Attention", b.attentionMs, attn);
    FillVariance(v, n, "FFN", b.ffnMs, ffn);
    FillVariance(v, n, "Logits", b.logitsMs, logits);
    FillVariance(v, n, "KV", b.kvMs, kv);
    FillVariance(v, n, "Weights", b.weightMovementMs, weights);
    FillVariance(v, n, "Sync", b.syncMs, sync);
    FillVariance(v, n, "Scheduler", b.schedulerMs, sched);
    FillVariance(v, n, "Verification", b.verificationMs, ver);
    char buf[900];
    int w = std::snprintf(buf, sizeof(buf),
                          "TARGET_BUDGET=%.2f\n  %-14s %7s %7s %8s\n",
                          b.total(), "name", "budget", "actual", "var");
    for (int i = 0; i < n && w < (int)sizeof(buf) - 64; ++i) {
        w += std::snprintf(buf + w, sizeof(buf) - w,
            "  %-14s %7.2f %7.2f %+7.2f %s\n", v[i].name, v[i].budgetMs,
            v[i].actualMs, v[i].varianceMs, v[i].bad ? "BAD" : "ok");
    }
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
