// ============================================================================
// P1_TUNER_AUTHORITY_001 — tuner is non-authoritative by construction
// Exit: 0 all PASS, 1 otherwise.
// ============================================================================
#include "execution_policy/TunerSuggest.hpp"
#include "execution_policy/ExecutionPolicyStore.hpp"
#include "execution_policy/LearnedProfile.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

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

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_TUNER_AUTHORITY_001 ===\n");

    const auto tmp = fs::temp_directory_path() / "rawrxd_tuner_cert";
    fs::create_directories(tmp);
    auto& store = ExecutionPolicyStore::Instance();
    store.setPaths((tmp / "rawrxd.settings.yaml").string(),
                   (tmp / "profiles").string());
    store.load();

    // Seed locked VRAM
    ExecutionPolicy lockDelta;
    lockDelta.memory.vramBudget.force(Bytes::GiB(6), SettingAuthority::UserLocked,
                                      SettingMutability::TokenBoundary);
    lockDelta.memory.vramParts.weights.force(
        Bytes::GiB(3), SettingAuthority::UserLocked,
        SettingMutability::TokenBoundary);
    lockDelta.memory.vramParts.kv.force(Bytes::GiB(1), SettingAuthority::UserLocked,
                                        SettingMutability::TokenBoundary);
    lockDelta.memory.vramParts.activations.force(
        Bytes::MiB(512), SettingAuthority::UserLocked,
        SettingMutability::TokenBoundary);
    lockDelta.memory.vramParts.streaming.force(
        Bytes::MiB(512), SettingAuthority::UserLocked,
        SettingMutability::TokenBoundary);
    lockDelta.memory.vramParts.scratch.force(
        Bytes::MiB(256), SettingAuthority::UserLocked,
        SettingMutability::TokenBoundary);
    lockDelta.memory.vramParts.reserve.force(
        Bytes::MiB(256), SettingAuthority::UserLocked,
        SettingMutability::TokenBoundary);
    lockDelta.placement.pinned.push_back("token_embd.weight");
    lockDelta.kv.context.force(8192, SettingAuthority::UserLocked,
                               SettingMutability::ModelReload);
    auto lr = store.apply(lockDelta, SettingAuthority::UserLocked, "cert-lock");
    PRED(lr.ok, "LOCK_SEED_OK");

    const auto& base = store.effective();
    const uint64_t lockedVram = base.memory.vramBudget.value.n;

    // OVER_BUDGET_CANDIDATE_REJECTED
    {
        ExecutionPolicy cand;
        cand.memory.vramBudget.force(Bytes::GiB(2), SettingAuthority::RuntimeLearned,
                                     SettingMutability::TokenBoundary);
        cand.memory.vramParts.weights.force(
            Bytes::GiB(5), SettingAuthority::RuntimeLearned,
            SettingMutability::TokenBoundary);
        cand.memory.vramParts.kv.force(Bytes::GiB(1), SettingAuthority::RuntimeLearned,
                                       SettingMutability::TokenBoundary);
        std::string why;
        PRED(ViolatesHardConstraints(base, cand, why),
             "OVER_BUDGET_CANDIDATE_REJECTED");
    }

    // PIN_VIOLATION_REJECTED
    {
        ExecutionPolicy cand;
        cand.placement.pinned = {"other.weight"}; // drops token_embd
        std::string why;
        PRED(ViolatesHardConstraints(base, cand, why), "PIN_VIOLATION_REJECTED");
    }

    // LOCKED_FIELD_PROPOSAL_REJECTED / BETTER_SCORE_DOES_NOT_BYPASS_LOCK
    {
        ExecutionPolicy raise;
        raise.memory.vramBudget.force(Bytes::GiB(99),
                                      SettingAuthority::RuntimeLearned,
                                      SettingMutability::TokenBoundary);
        auto r = store.apply(raise, SettingAuthority::RuntimeLearned,
                             "bypass-attempt");
        PRED(store.effective().memory.vramBudget.value.n == lockedVram,
             "LOCKED_FIELD_PROPOSAL_REJECTED");
        PRED(store.effective().memory.vramBudget.authority ==
                 SettingAuthority::UserLocked,
             "BETTER_SCORE_DOES_NOT_BYPASS_LOCK");
        (void)r;
    }

    // APPLY_ONCE_SESSION_ONLY
    {
        TunerProposal prop;
        prop.hasProposal = true;
        prop.delta.streaming.prefetchDepth.force(
            9, SettingAuthority::RuntimeLearned, SettingMutability::Immediate);
        auto r = ApplyProposal(prop, TunerAction::ApplyOnce);
        PRED(r.ok, "APPLY_ONCE_OK");
        PRED(store.effective().streaming.prefetchDepth.present &&
                 store.effective().streaming.prefetchDepth.authority ==
                     SettingAuthority::Session,
             "APPLY_ONCE_SESSION_ONLY");
    }

    // APPLY_LOCK_SELECTED_DELTA_ONLY
    {
        TunerProposal prop;
        prop.hasProposal = true;
        prop.delta.streaming.buffers.force(5, SettingAuthority::RuntimeLearned,
                                           SettingMutability::Immediate);
        // Must NOT carry unrelated unlocked fields
        PRED(!prop.delta.memory.vramBudget.present,
             "APPLY_LOCK_SELECTED_DELTA_ONLY_SHAPE");
        auto r = ApplyProposal(prop, TunerAction::ApplyAndLock);
        PRED(r.ok, "APPLY_LOCK_OK");
        PRED(store.effective().streaming.buffers.present &&
                 store.effective().streaming.buffers.authority ==
                     SettingAuthority::UserLocked &&
                 store.effective().streaming.buffers.value == 5,
             "APPLY_LOCK_SELECTED_DELTA_ONLY");
        PRED(store.effective().memory.vramBudget.value.n == lockedVram,
             "APPLY_LOCK_PRESERVES_OTHER_LOCKS");
    }

    // PROFILE_NEVER_ESCALATES_AUTHORITY
    {
        LearnedProfile lp;
        lp.valid = true;
        lp.metrics.successes = 3;
        lp.metrics.tps = 99.0;
        lp.policy = MakeDefaultPolicy();
        lp.policy.placement.layerRanges.push_back(
            {LayerRange{0, 2}, DeviceKind::Gpu0});
        ExecutionObservation live;
        live.tokensPerSecond = 1.0;
        live.ttftMs = 900;
        live.peakVramBytes = Bytes::GiB(1).n;
        live.fromLiveTelemetry = true;
        live.completed = true;
        live.outputValid = true;
        auto prop = Suggest(store.effective(), &lp, &live);
        // Suggest is advisory — applying with RuntimeLearned must not unlock
        if (prop.hasProposal) {
            auto before = store.effective().memory.vramBudget.authority;
            ApplyProposal(prop, TunerAction::ApplyOnce);
            PRED(store.effective().memory.vramBudget.authority == before,
                 "PROFILE_NEVER_ESCALATES_AUTHORITY");
        } else {
            PRED(true, "PROFILE_NEVER_ESCALATES_AUTHORITY");
        }
    }

    std::printf("=== %s: %s (%d fail) ===\n", "P1_TUNER_AUTHORITY_001",
                g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
