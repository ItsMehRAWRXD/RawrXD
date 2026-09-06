// ============================================================================
// TunerSuggest.hpp — multi-dimensional score; hard constraints before scoring
// INV-6 advisory until Apply; INV-7 Session; INV-8 lock only selected deltas
// ============================================================================
#pragma once

#include "AutoPlanner.hpp"
#include "ExecutionObservation.hpp"
#include "LearnedProfile.hpp"
#include "LearnedProfileStore.hpp"
#include "ExecutionPolicyStore.hpp"
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace Deep2 {
namespace Exec {

enum class TunerAction : uint8_t {
    Ignore = 0,
    ApplyOnce,
    ApplyAndLock,
    SaveProfile
};

struct TunerProposal {
    bool hasProposal = false;
    bool rejected = false;
    ExecutionPolicy delta; // ONLY selected tunables (INV-8)
    std::string rationale;
    double score = 0.0;
    double vramGbBefore = 0, vramGbAfter = 0;
    double ramGbBefore = 0, ramGbAfter = 0;
    double tpsBefore = 0, tpsEst = 0;
    double ttftMsBefore = 0, ttftMsEst = 0;
};

inline bool ViolatesHardConstraints(const ExecutionPolicy& base,
                                    const ExecutionPolicy& cand,
                                    std::string& why) {
    ExecutionPolicy merged = base;
    // Lightweight merge of present cand fields for Validate.
    if (cand.memory.vramBudget.present)
        merged.memory.vramBudget = cand.memory.vramBudget;
    if (cand.memory.vramParts.weights.present ||
        cand.memory.vramParts.kv.present)
        merged.memory.vramParts = cand.memory.vramParts;
    if (cand.memory.ramBudget.present)
        merged.memory.ramBudget = cand.memory.ramBudget;
    if (cand.kv.context.present) merged.kv.context = cand.kv.context;
    if (!cand.placement.pinned.empty())
        merged.placement.pinned = cand.placement.pinned;

    auto v = Validate(merged);
    if (!v.ok) {
        why = v.detail;
        return true;
    }
    // INV-10: never shrink context below requested locked context.
    if (base.kv.context.present &&
        base.kv.context.authority == SettingAuthority::UserLocked &&
        cand.kv.context.present &&
        cand.kv.context.value < base.kv.context.value) {
        why = "violates locked context";
        return true;
    }
    // INV-9/10: never drop explicit pins.
    for (const auto& pin : base.placement.pinned) {
        bool kept = cand.placement.pinned.empty();
        if (!cand.placement.pinned.empty()) {
            kept = false;
            for (const auto& p : cand.placement.pinned)
                if (p == pin) {
                    kept = true;
                    break;
                }
        }
        if (!kept && !cand.placement.pinned.empty()) {
            why = "violates explicit pin";
            return true;
        }
    }
    return false;
}

inline double ScoreCandidate(double tpsGain, double ttftMsDelta,
                             double vramPressure, double ramPressure,
                             double migrationPenalty, double nvmePenalty,
                             double instability) {
    return tpsGain * 1.0 - (ttftMsDelta / 1000.0) * 0.5 -
           vramPressure * 2.0 - ramPressure * 1.0 - migrationPenalty * 0.3 -
           nvmePenalty * 0.4 - instability * 0.5;
}

inline TunerProposal Suggest(const ExecutionPolicy& current,
                             const LearnedProfile* learned,
                             const ExecutionObservation* live = nullptr) {
    TunerProposal best;
    best.vramGbBefore = current.memory.vramBudget.present
                            ? current.memory.vramBudget.value.n / (double)GB
                            : 12.0;
    best.ramGbBefore = current.memory.ramBudget.present
                           ? current.memory.ramBudget.value.n / (double)GB
                           : 40.0;
    best.tpsBefore =
        live ? live->tokensPerSecond : (learned ? learned->metrics.tps : 0);
    best.ttftMsBefore =
        live ? live->ttftMs : (learned ? learned->metrics.ttftMs : 0);

    struct Cand {
        ExecutionPolicy delta;
        std::string why;
        double tpsEst = 0, ttftEst = 0, vramAfter = 0, ramAfter = 0;
        double score = 0;
    };
    std::vector<Cand> cands;

    if (learned && learned->valid && learned->metrics.successes > 0 &&
        !learned->policy.placement.layerRanges.empty()) {
        Cand c;
        // INV-8: only placement ranges as selected tunable, not full policy.
        c.delta.placement.layerRanges = learned->policy.placement.layerRanges;
        c.why = "Reuse observed hw×model placement";
        c.tpsEst = learned->metrics.tps;
        c.ttftEst = learned->metrics.ttftMs;
        c.vramAfter = learned->metrics.peakVramBytes
                          ? learned->metrics.peakVramBytes / (double)GB
                          : best.vramGbBefore;
        c.ramAfter = learned->metrics.peakRamBytes
                         ? learned->metrics.peakRamBytes / (double)GB
                         : best.ramGbBefore;
        cands.push_back(c);
    }

    if (live && live->fromLiveTelemetry &&
        current.memory.vramBudget.present) {
        const double peakFrac =
            (double)live->peakVramBytes /
            (double)current.memory.vramBudget.value.n;
        if (peakFrac > 0.92 && current.streaming.chunkSize.present) {
            Cand c;
            const uint64_t next = (std::max)(
                16ULL * MB, current.streaming.chunkSize.value.n / 2);
            c.delta.streaming.chunkSize.force(
                Bytes::Of(next), SettingAuthority::RuntimeLearned,
                SettingMutability::Immediate);
            c.why = "Live peak VRAM >92% — halve stream chunk";
            c.tpsEst = best.tpsBefore * 0.95;
            c.ttftEst = best.ttftMsBefore * 1.05;
            c.vramAfter = best.vramGbBefore * 0.85;
            c.ramAfter = best.ramGbBefore;
            cands.push_back(c);
        } else if (peakFrac < 0.70 && live->migrations < 3) {
            Cand c;
            const int depth = current.streaming.prefetchDepth.present
                                  ? current.streaming.prefetchDepth.value + 1
                                  : 4;
            c.delta.streaming.prefetchDepth.force(
                depth, SettingAuthority::RuntimeLearned,
                SettingMutability::Immediate);
            c.why = "Live VRAM headroom — deepen prefetch";
            c.tpsEst = best.tpsBefore > 0 ? best.tpsBefore * 1.10 : 0;
            c.ttftEst = best.ttftMsBefore > 0 ? best.ttftMsBefore * 0.90 : 0;
            c.vramAfter = best.vramGbBefore * 0.78;
            c.ramAfter = best.ramGbBefore;
            cands.push_back(c);
        }
        if (live->spillToNvme > 0 || live->streamChurnBytes > (256ULL << 20) ||
            live->nvmePhysicalReadBytes > (256ULL << 20)) {
            Cand c;
            c.delta.streaming.buffers.force(
                (std::max)(3, current.streaming.buffers.present
                                   ? current.streaming.buffers.value + 1
                                   : 3),
                SettingAuthority::RuntimeLearned,
                SettingMutability::Immediate);
            c.why = "NVMe spill pressure — add stream buffer";
            c.tpsEst = best.tpsBefore * 1.05;
            c.ttftEst = best.ttftMsBefore * 0.95;
            c.vramAfter = best.vramGbBefore;
            c.ramAfter = best.ramGbBefore * 1.05;
            cands.push_back(c);
        }
    }

    for (auto& c : cands) {
        std::string whyReject;
        if (ViolatesHardConstraints(current, c.delta, whyReject)) {
            best.rejected = true;
            best.rationale = std::string("reject: ") + whyReject;
            continue;
        }
        const double tpsGain = c.tpsEst - best.tpsBefore;
        const double ttftDelta = c.ttftEst - best.ttftMsBefore;
        const double vPress =
            best.vramGbBefore > 0 ? c.vramAfter / best.vramGbBefore : 0;
        const double rPress =
            best.ramGbBefore > 0 ? c.ramAfter / best.ramGbBefore : 0;
        const double mig =
            live ? (double)live->migrations * 0.1 : 0.0;
        const double nvme =
            live ? (double)live->nvmePhysicalReadBytes / (double)GB : 0.0;
        const double churn =
            live ? (double)live->streamChurnBytes / (double)GB : 0.0;
        c.score = ScoreCandidate(tpsGain, ttftDelta, vPress, rPress, mig,
                                 nvme + churn * 0.5,
                                 live ? (double)live->residencyMisses * 0.05
                                      : 0.0);
        if (!best.hasProposal || c.score > best.score) {
            best.hasProposal = true;
            best.delta = c.delta;
            best.rationale = c.why;
            best.score = c.score;
            best.tpsEst = c.tpsEst;
            best.ttftMsEst = c.ttftEst;
            best.vramGbAfter = c.vramAfter;
            best.ramGbAfter = c.ramAfter;
        }
    }
    return best;
}

// Back-compat wrapper (RunMetrics → thin observation)
inline TunerProposal Suggest(const ExecutionPolicy& current,
                             const LearnedProfile* learned,
                             const RunMetrics* liveMetrics) {
    ExecutionObservation o;
    if (liveMetrics) {
        o.tokensPerSecond = liveMetrics->tps;
        o.ttftMs = liveMetrics->ttftMs;
        o.peakVramBytes = liveMetrics->peakVramBytes;
        o.peakRamBytes = liveMetrics->peakRamBytes;
        o.fromLiveTelemetry = liveMetrics->peakVramBytes > 0;
        o.completed = true;
        o.outputValid = true;
    }
    return Suggest(current, learned, liveMetrics ? &o : nullptr);
}

inline std::string FormatProposal(const TunerProposal& p) {
    if (!p.hasProposal)
        return p.rejected ? p.rationale : "No suggestion.";
    char buf[640];
    std::snprintf(
        buf, sizeof(buf),
        "%s\nscore=%.3f\n\nVRAM: %.2f → %.2f GB\nRAM:  %.1f → %.1f GB\n"
        "TPS:  %.1f → estimated %.1f\nTTFT: %.0f → estimated %.0f ms",
        p.rationale.c_str(), p.score, p.vramGbBefore, p.vramGbAfter,
        p.ramGbBefore, p.ramGbAfter, p.tpsBefore, p.tpsEst, p.ttftMsBefore,
        p.ttftMsEst);
    return buf;
}

inline PolicyCommitResult ApplyProposal(const TunerProposal& prop,
                                        TunerAction action,
                                        const HardwareSnapshot* hw = nullptr,
                                        const std::string* modelFp = nullptr) {
    if (!prop.hasProposal || action == TunerAction::Ignore) {
        PolicyCommitResult r;
        r.detail = "ignored";
        return r;
    }
    // INV-7 Session; INV-8 UserLocked only for selected delta fields.
    SettingAuthority auth = SettingAuthority::RuntimeLearned;
    if (action == TunerAction::ApplyAndLock)
        auth = SettingAuthority::UserLocked;
    else if (action == TunerAction::ApplyOnce)
        auth = SettingAuthority::Session;

    auto r = ExecutionPolicyStore::Instance().apply(prop.delta, auth,
                                                    "tuner-suggest");
    if (r.ok && action == TunerAction::SaveProfile && hw && modelFp) {
        LearnedProfile lp;
        lp.hardware = *hw;
        if (lp.hardware.fingerprint.empty())
            lp.hardware.fingerprint = MakeHardwareFingerprint(*hw);
        lp.modelFingerprint = *modelFp;
        lp.policy = ExecutionPolicyStore::Instance().effective();
        lp.policySha = r.policySha;
        lp.valid = true;
        LearnedProfileStore::Instance().save(lp);
        r.detail += "; profile saved";
    }
    return r;
}

} // namespace Exec
} // namespace Deep2
