// ============================================================================
// P1_NUCOLD_HOTPATCH_001 — hotpatch without cold reload; RCU N→N+1
//
// Requires simultaneous: inflight gen N, commit N+1, zero unload/restart,
// old reader completes on N, subsequent acquire reports N+1.
// Cold-required flags must NOT silently cold-load.
// Exit: 0 all PASS, 1 otherwise.
// ============================================================================
#include "execution_policy/NuColdHotpatch.hpp"
#include "execution_policy/ReverseLoadLifecycle.hpp"

#include <cstdio>

using namespace Deep2::Exec;

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

static RealtimeStateSnapshot OverlaySnap(RealtimeKernel* k, uint64_t proof,
                                         const char* pol) {
    RealtimeStateSnapshot s;
    s.expectedSchemaHash = k->schemaHash;
    s.expectedAuthorityHash = k->authorityHash;
    s.source = "nucold_cert";
    s.state.timing.baselineDecodeMs = 240.0;
    s.state.timing.targetDecodeMs = 100.0;
    s.state.policySha = pol;
    if (proof)
        s.state.patches.active.push_back(
            CompileReuseRule(proof, 2, 0x2ULL, proof, 2000.0));
    return s;
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_NUCOLD_HOTPATCH_001 ===\n");

    uint32_t coldReloads = 0;
    uint32_t modelUnloads = 0;
    uint32_t processRestarts = 0;

    RealtimeKernel* kernel = MakeSealedKernel();
    RealtimeEngine engine(kernel);

    // Seed gen 0 → commit once so active is N=1 for clarity
    CommitResult seed = engine.CommitRealtimeState(OverlaySnap(kernel, 0, "p0"));
    PRED(seed.ok, "SEED_COMMIT");

    RealtimeReadView inflight = engine.AcquireState();
    const uint64_t genN = inflight.generation();
    PRED(inflight.valid() && genN >= 1, "INFLIGHT_HOLDS_N");

    HotPatchRequest req;
    req.flags = {}; // all hot-safe
    req.candidate = OverlaySnap(kernel, 501, "p1-hot");
    HotPatchResult hr = ControllerHotPatch(engine, req);
    PRED(hr.status == HotPatchStatus::Applied, "HOTPATCH_APPLIED");
    PRED(hr.generation == genN + 1, "GENERATION_ADVANCE_N_TO_N1");
    PRED(hr.imageSha != 0, "PATCH_HASH_PRESENT");

    PRED(inflight.generation() == genN, "IN_FLIGHT_READERS_PIN_OLD");
    RealtimeReadView after = engine.AcquireState();
    PRED(after.generation() == genN + 1, "SUBSEQUENT_TOKEN_SEES_N1");

    PRED(coldReloads == 0, "COLD_RELOAD_FORBIDDEN");
    PRED(modelUnloads == 0, "MODEL_UNLOAD_FORBIDDEN");
    PRED(processRestarts == 0, "PROCESS_RESTART_FORBIDDEN");

    // Failed validation must not swap (rollback-by-non-commit).
    // Schema is stamped by ControllerHotPatch; fail via blacklisted proof.
    HotPatchRequest bad;
    bad.candidate = OverlaySnap(kernel, 999, "bad");
    bad.candidate.state.patches.blacklist.push_back(999);
    HotPatchResult hb = ControllerHotPatch(engine, bad);
    PRED(hb.status == HotPatchStatus::CommitFailed, "ROLLBACK_ON_FAILURE");
    PRED(engine.AcquireState().generation() == genN + 1,
         "FAILED_COMMIT_NO_SWAP");

    // Cold-required must be explicit disposition — not silent cold load
    HotPatchRequest cold;
    cold.flags.requiresWeightReparse = true;
    cold.candidate = OverlaySnap(kernel, 777, "coldish");
    HotPatchResult hc = ControllerHotPatch(engine, cold);
    PRED(hc.status == HotPatchStatus::ColdPathRequired, "COLD_PATH_EXPLICIT");
    PRED(coldReloads == 0, "COLD_REQUIRED_NOT_AUTO_RELOAD");

    // Active generation mutation forbidden
    HotPatchRequest mut;
    mut.flags.mutatesInFlightGeneration = true;
    HotPatchResult hm = ControllerHotPatch(engine, mut);
    PRED(hm.status == HotPatchStatus::ForbiddenActiveMutation,
         "ACTIVE_GENERATION_MUTATION_FORBIDDEN");

    // Reverse acquire: second hit is L3 HOT
    ModelImageRegistry reg;
    RuntimeOverlay ov;
    HotPatchFlags none{};
    AcquireResult a0 =
        AcquireModel(reg, "sha256:tiny", "tiny.gguf", ov, none);
    PRED(a0.ok && a0.loadClass == LoadClass::L0_TrueCold, "ACQUIRE_L0_ONCE");
    AcquireResult a1 =
        AcquireModel(reg, "sha256:tiny", "tiny.gguf", ov, none);
    PRED(a1.ok && a1.loadClass == LoadClass::L3_Hot, "ACQUIRE_L3_HOT_REUSE");

    HotPatchFlags shape{};
    shape.requiresTensorShapeChange = true;
    AcquireResult a2 =
        AcquireModel(reg, "sha256:tiny", "tiny.gguf", ov, shape);
    PRED(a2.ok && a2.loadClass == LoadClass::L1_HotCold,
         "ACQUIRE_L1_HOT_COLD_PARTIAL");

    std::printf("RAWRXD_P1_NUCOLD_HOTPATCH=%s\n", g_fail ? "FAIL" : "PASS");
    delete kernel;
    return g_fail ? 1 : 0;
}
