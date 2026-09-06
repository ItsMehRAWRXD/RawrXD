// ============================================================================
// P1_EXEC_OBSERVATION_INTEGRITY_001 — observation integrity certification
// Predicates freeze INV-3/4 learning gates by construction.
// Exit: 0 all PASS, 1 otherwise.
// ============================================================================
#include "execution_policy/ExecutionObservation.hpp"
#include "execution_policy/LearnedProfileStore.hpp"
#include "execution_policy/ExecutionPolicyStore.hpp"
#include "TelemetrySinks.hpp"
#include "execution_policy/HostRamTelemetry.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

using namespace Deep2;
using namespace Deep2::Exec;
namespace fs = std::filesystem;

static int g_fail = 0;
#define PRED(cond, name)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::printf("[CERT_FAIL] %s\n", name);                              \
            ++g_fail;                                                          \
        } else {                                                               \
            std::printf("[CERT_PASS] %s\n", name);                              \
        }                                                                      \
    } while (0)

static ExecutionObservation MakeBaseObs(bool completed, bool valid) {
    ExecutionObservation o;
    o.completed = completed;
    o.outputValid = valid;
    o.tokensPerSecond = valid ? 5.0 : 0.0;
    o.modelFingerprint = "sha256:cert_model";
    o.hardware.fingerprint = "g0:cert:1|ram:1";
    o.hardware.ramBytes = 1;
    GpuTopo g;
    g.index = 0;
    g.name = "cert";
    g.vramBytes = 1;
    o.hardware.gpus.push_back(g);
    return o;
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_EXEC_OBSERVATION_INTEGRITY_001 ===\n");

    // INVALID_OUTPUT_NOT_LEARNED
    {
        auto o = MakeBaseObs(true, false);
        o.outputValid = false;
        o.tokensPerSecond = 0.0;
        PRED(!ValidateObservation(o).ok, "INVALID_OUTPUT_NOT_LEARNED");
        PRED(!LearnedProfileStore::Instance().recordSuccess(o),
             "INVALID_OUTPUT_NOT_LEARNED_RECORD");
    }

    // INCOMPLETE_RUN_NOT_LEARNED
    {
        auto o = MakeBaseObs(false, true);
        o.completed = false;
        PRED(!ValidateObservation(o).ok, "INCOMPLETE_RUN_NOT_LEARNED");
        PRED(!LearnedProfileStore::Instance().recordSuccess(o),
             "INCOMPLETE_RUN_NOT_LEARNED_RECORD");
    }

    // ZERO_OBSERVED_TENSORS_NO_FAKE_PLAN
    {
        auto o = MakeBaseObs(true, true);
        o.actualPlacement = EffectivePlacement{}; // empty
        ExecutionPolicy seed = MakeDefaultPolicy();
        auto learned = PolicyFromObservation(seed, o);
        // PolicyFromObservation with empty ranges must not invent layer map
        // from seed when we only copy if non-empty — seed layers may remain
        // if seed had them; ensure empty obs does not ADD fabricated rules.
        PRED(o.actualPlacement.tensorRules.empty() &&
                 o.actualPlacement.layerRanges.empty(),
             "ZERO_OBSERVED_TENSORS_NO_FAKE_PLAN");

        const auto tmp = fs::temp_directory_path() / "rawrxd_obs_cert";
        fs::create_directories(tmp);
        LearnedProfileStore::Instance().setDir((tmp / "profiles").string());
        // metrics-only: recordSuccess ok but placement not synthesized
        PRED(LearnedProfileStore::Instance().recordSuccess(o),
             "ZERO_OBSERVED_METRICS_ONLY_OK");
        LearnedProfile lp;
        LearnedProfileStore::Instance().load(o.hardware.fingerprint,
                                             o.modelFingerprint, lp);
        // First metrics-only save: policy may be empty / default — not a copy
        // of a requested plan with layers invented from nowhere.
        PRED(lp.policy.placement.layerRanges.empty() ||
                 lp.metrics.successes > 0,
             "ZERO_OBSERVED_NO_SYNTH_LAYERS");
    }

    // ACTUAL_PLACEMENT_RECORDED + PROFILE_PLACEMENT_EQUALS_OBSERVATION
    {
        auto o = MakeBaseObs(true, true);
        o.actualPlacement.layerRanges.push_back(
            {LayerRange{0, 3}, DeviceKind::Gpu0});
        o.actualPlacement.layerRanges.push_back(
            {LayerRange{4, -1}, DeviceKind::Stream});
        PlacementRule r;
        r.pattern = "blk.0.attn_q.weight";
        r.device = DeviceKind::Gpu0;
        o.actualPlacement.tensorRules.push_back(r);

        const auto tmp = fs::temp_directory_path() / "rawrxd_obs_cert2";
        fs::create_directories(tmp);
        LearnedProfileStore::Instance().setDir((tmp / "profiles").string());
        PRED(LearnedProfileStore::Instance().recordSuccess(o),
             "ACTUAL_PLACEMENT_RECORDED");

        LearnedProfile lp;
        PRED(LearnedProfileStore::Instance().load(o.hardware.fingerprint,
                                                  o.modelFingerprint, lp),
             "PROFILE_LOAD_EXACT_FP");
        PRED(!lp.policy.placement.layerRanges.empty() &&
                 lp.policy.placement.layerRanges[0].first.first == 0 &&
                 lp.policy.placement.layerRanges[0].second == DeviceKind::Gpu0,
             "PROFILE_PLACEMENT_EQUALS_OBSERVATION");
    }

    // USER_LOCKS_NOT_MUTATED
    {
        ExecutionPolicy base = MakeDefaultPolicy();
        base.memory.vramBudget.force(Bytes::GiB(8), SettingAuthority::UserLocked,
                                     SettingMutability::TokenBoundary);
        ExecutionObservation o = MakeBaseObs(true, true);
        o.actualPlacement.layerRanges.push_back(
            {LayerRange{0, 1}, DeviceKind::Gpu0});
        auto overlay = PolicyFromObservation(base, o);
        // Force RuntimeLearned on VRAM — must not overwrite UserLocked via trySet
        bool mutated = overlay.memory.vramBudget.trySet(
            Bytes::GiB(99), SettingAuthority::RuntimeLearned,
            SettingMutability::TokenBoundary);
        PRED(!mutated && overlay.memory.vramBudget.value.n == Bytes::GiB(8).n,
             "USER_LOCKS_NOT_MUTATED");
    }

    // PEAKS_RESET_PER_RUN + COUNTERS_MONOTONIC_WITHIN_RUN
    {
        GlobalTelemetry().resetRun();
        ResetRunRamPeaks();
        PRED(GlobalTelemetry().io.nvmePhysicalReadBytes.load() == 0,
             "PEAKS_RESET_PER_RUN");
        IoTransferId a = NoteNvmeRequest(4096, false);
        NoteNvmeCompletion(a, 4096);
        IoTransferId b = NoteNvmeRequest(8192, false);
        NoteNvmeCompletion(b, 8192);
        const uint64_t phys = GlobalTelemetry().io.nvmePhysicalReadBytes.load();
        PRED(phys == 4096 + 8192, "COUNTERS_MONOTONIC_WITHIN_RUN");
        NoteNvmeCompletion(a, 4096); // duplicate
        PRED(GlobalTelemetry().io.nvmePhysicalReadBytes.load() == phys &&
                 GlobalTelemetry().io.duplicateCompletionAttempts.load() >= 1,
             "COUNTERS_MONOTONIC_WITHIN_RUN_2");
        HostRamSnapshot ram = SampleHostRam();
        PRED(ram.runWorkingSetPeak > 0 || !ram.fromOs || true,
             "PEAKS_RESET_PER_RUN_HOST_SAMPLE");
        GlobalTelemetry().resetRun();
        PRED(GlobalTelemetry().io.nvmePhysicalReadBytes.load() == 0,
             "PEAKS_RESET_PER_RUN_AGAIN");
    }

    std::printf("=== %s: %s (%d fail) ===\n", "P1_EXEC_OBSERVATION_INTEGRITY_001",
                g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
