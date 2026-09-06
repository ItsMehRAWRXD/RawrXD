// ============================================================================
// ExecutionPolicyBridge.hpp — thin accessor for Loader / Streamer / MARS / IDE
// ============================================================================
#pragma once

#include "ExecutionPolicy.hpp"
#include "ExecutionPolicyStore.hpp"
#include "AutoPlanner.hpp"
#include "LearnedProfileStore.hpp"

#include <algorithm>
#include <filesystem>

namespace Deep2 {
namespace Exec {

inline const ExecutionPolicy& ActivePolicy() {
    return ExecutionPolicyStore::Instance().effective();
}

// Optional: set before EnsurePolicyLoaded to bind hw×model profiles.
inline HardwareSnapshot& ActiveHardwareSnapshot() {
    static HardwareSnapshot hw;
    return hw;
}

inline bool EnsurePolicyLoaded(const std::string& modelFingerprint = {}) {
    auto& store = ExecutionPolicyStore::Instance();
    const char* candidates[] = {
        "config/rawrxd.settings.yaml",
        "rawrxd.settings.yaml",
        nullptr
    };
    bool loaded = false;
    for (int i = 0; candidates[i]; ++i) {
        if (std::filesystem::exists(candidates[i])) {
            store.setPaths(candidates[i], "profiles");
            loaded = store.load(modelFingerprint);
            break;
        }
    }
    if (!loaded && !modelFingerprint.empty())
        store.setModelFingerprint(modelFingerprint);

    LearnedProfileStore::Instance().setDir("profiles");

    LearnedProfile learned;
    const auto& hw = ActiveHardwareSnapshot();
    const std::string hwFp = hw.fingerprint.empty() && !hw.gpus.empty()
                                 ? MakeHardwareFingerprint(hw)
                                 : hw.fingerprint;
    const std::string mfp = !modelFingerprint.empty()
                                ? modelFingerprint
                                : store.modelFingerprint();
    bool haveLearned = false;
    if (!hwFp.empty() && !mfp.empty())
        haveLearned = LearnedProfileStore::Instance().load(hwFp, mfp, learned);

    // AUTO: derive Expert knobs; prefer fingerprint-bound placement when present.
    if (store.effective().mode == UiMode::Auto &&
        store.effective().placement.layerRanges.empty()) {
        AutoPlanHints hints;
        hints.gpuCount =
            (std::max)(1, (int)store.effective().memory.gpus.size());
        if (!hw.gpus.empty())
            hints.gpuCount = (int)hw.gpus.size();
        auto planned =
            haveLearned ? AutoPlanFromLearned(store.effective(), learned, hints)
                        : AutoPlan(store.effective(), hints);
        planned.mode = UiMode::Auto;
        store.apply(planned, SettingAuthority::AutoPlanner, "auto-plan");
    } else if (haveLearned && store.effective().mode == UiMode::Auto &&
               store.effective().scheduler.respectOverrides.present &&
               store.effective().scheduler.respectOverrides.value) {
        // RESPECT OVERRIDES: still allow RuntimeLearned fill for empty cells.
        auto planned = AutoPlanFromLearned(store.effective(), learned, {});
        planned.mode = UiMode::Auto;
        store.apply(planned, SettingAuthority::RuntimeLearned,
                    "learned-seed");
    }
    return true;
}

inline PolicyCommitResult ApplySessionDelta(const ExecutionPolicy& delta,
                                            const std::string& reason) {
    return ExecutionPolicyStore::Instance().apply(
        delta, SettingAuthority::Session, reason);
}

inline bool PolicyAllowsWorkAvoidance() {
    const auto& p = ActivePolicy();
    if (!p.reuse.enabled.present || !p.reuse.enabled.value) return false;
    if (!p.reuse.mode.present) return false;
    return p.reuse.mode.value == ReuseMode::ExactOnly ||
           p.reuse.mode.value == ReuseMode::CertifiedReuse;
}

inline uint64_t PolicyVramHardCapBytes() {
    const auto& p = ActivePolicy();
    if (!p.memory.vramBudget.present) return 0;
    if (p.memory.vramCapKind.present &&
        p.memory.vramCapKind.value == CapKind::Soft)
        return 0; // soft: no hard enforcement via this helper
    return p.memory.vramBudget.value.n;
}

inline uint64_t PolicyRamHardCapBytes() {
    const auto& p = ActivePolicy();
    if (p.memory.ram.hardCap.present) return p.memory.ram.hardCap.value.n;
    if (!p.memory.ramBudget.present) return 0;
    if (p.memory.ramCapKind.present &&
        p.memory.ramCapKind.value == CapKind::Soft)
        return 0;
    return p.memory.ramBudget.value.n;
}

inline int PolicyContextTokens() {
    const auto& p = ActivePolicy();
    if (p.kv.context.present && p.kv.context.value > 0)
        return p.kv.context.value;
    if (p.context.present && p.context.value > 0)
        return p.context.value;
    return 0;
}

inline bool PolicyStreamingEnabled() {
    const auto& p = ActivePolicy();
    if (p.streaming.enabled.present) return p.streaming.enabled.value;
    return true;
}

} // namespace Exec
} // namespace Deep2
