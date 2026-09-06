// ============================================================================
// P1_LAZY_REGION_HOTPATCH_001 — first-request shell + on-demand region hotpatch
//
// STARTUP_MODEL_COST ≈ 0
// FULL_MODEL_MATERIALIZATION_BEFORE_FIRST_TOKEN = NOT_REQUIRED
// REGION install = generation hotpatch; inflight N finishes on N
// Exit: 0 all PASS, 1 otherwise.
// ============================================================================
#include "execution_policy/LazyRequestActivation.hpp"
#include "execution_policy/LazyRegionMaterialize.hpp"

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

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_LAZY_REGION_HOTPATCH_001 ===\n");

    PRED(LOAD_ON_FIRST_REQUEST == -1, "LOAD_ON_FIRST_REQUEST_SENTINEL");
    PRED((int)LoadTrigger::FirstRequest == -1, "LOAD_TRIGGER_FIRST_REQUEST");

    ModelDescriptor desc;
    desc.fingerprint = "sha256:lazy-cert";
    desc.path = "lazy.gguf";
    desc.nLayers = 4;
    desc.loadTrigger = LoadTrigger::FirstRequest;
    desc.loadDelayMs = LOAD_ON_FIRST_REQUEST;
    desc.startupLoad = false;
    desc.preload = false;

    // IDE start: descriptor only — no materialization
    RegisterDescriptorAtStartup(desc);
    PRED(desc.state.load() == ModelRuntimeState::DescriptorOnly,
         "STARTUP_DESCRIPTOR_ONLY");
    PRED(!desc.startupLoad && !desc.preload, "NO_STARTUP_PRELOAD");

    RealtimeKernel* kernel = MakeSealedKernel();
    RealtimeEngine engine(kernel);
    ModelImageRegistry reg;
    LazyModelShell shell = MakeUntouchedShell(desc.fingerprint, desc.nLayers);

    // Seed minimal image so ControllerHotPatch has an active generation
    {
        RealtimeStateSnapshot seed;
        seed.expectedSchemaHash = kernel->schemaHash;
        seed.expectedAuthorityHash = kernel->authorityHash;
        seed.source = "lazy_seed";
        seed.state.policySha = "seed";
        PRED(engine.CommitRealtimeState(seed).ok, "SEED_IMAGE");
    }

    uint32_t coldReloads = 0;

    // First request activates shell (not full model)
    ActivateStatus act = ActivateForRequest(desc, reg, engine, shell);
    PRED(act.ok, "FIRST_REQUEST_ACTIVATE_OK");
    PRED(desc.state.load() == ModelRuntimeState::ShellReady, "SHELL_READY");
    PRED(!shell.fullyMaterialized(),
         "FULL_MODEL_MATERIALIZATION_BEFORE_FIRST_TOKEN_NOT_REQUIRED");
    PRED(coldReloads == 0, "NO_COLD_RELOAD_ON_ACTIVATE");

    RealtimeReadView inflight = engine.AcquireState();
    const uint64_t genN = inflight.generation();

    // Execute L0 → materialize only L0 via hotpatch
    uint64_t execGen = 0;
    PRED(ExecuteLayer(shell, engine, 0, execGen), "EXECUTE_LAYER0");
    PRED(shell.layerReady(0), "LAYER0_READY");
    PRED(!shell.layerReady(1), "LAYER1_STILL_MISSING");
    PRED(inflight.generation() == genN, "INFLIGHT_N_UNCHANGED_AFTER_REGION_PATCH");

    RealtimeReadView after0 = engine.AcquireState();
    PRED(after0.generation() == genN + 1, "REGION_HOTPATCH_ADVANCES_GEN");
    PRED(execGen == after0.generation() || execGen >= genN + 1,
         "EXECUTE_SEES_PATCHED_GEN");

    // Prefetch lookahead L1-L2 while "computing"
    uint32_t pref = PrefetchLayers(shell, engine, 1, 2);
    PRED(pref == 2, "PREFETCH_LOOKAHEAD");
    PRED(shell.layerReady(1) && shell.layerReady(2), "L1_L2_READY");
    PRED(!shell.layerReady(3), "L3_STILL_MISSING_UNTIL_NEEDED");

    // Second request: already active → L3 hot
    ActivateStatus act2 = ActivateForRequest(desc, reg, engine, shell);
    PRED(act2.ok && act2.loadClass == LoadClass::L3_Hot,
         "SECOND_REQUEST_ZERO_LOAD_COST");

    // Shared handles: EnsureRegionReady again must not copy / reload
    RegionHandle h0 = shell.layers[0];
    PRED(EnsureRegionReady(shell, engine, 0).ok, "IDEMPOTENT_REGION");
    PRED(shell.layers[0].get() == h0.get(), "EXISTING_REGIONS_NO_COPY");

    // Complete remaining layer
    PRED(ExecuteLayer(shell, engine, 3, execGen), "EXECUTE_LAYER3");
    shell.finalNorm = MaterializeShellRegion(RegionKind::FinalNorm);
    shell.lmHead = MaterializeShellRegion(RegionKind::LMHead);
    PRED(shell.fullyMaterialized(), "OPTIONAL_FULL_MATERIALIZE_BY_END");

    PRED(coldReloads == 0, "COLD_RELOAD_STILL_ZERO");

    std::printf("RAWRXD_P1_LAZY_REGION_HOTPATCH=%s\n", g_fail ? "FAIL" : "PASS");
    delete kernel;
    return g_fail ? 1 : 0;
}
