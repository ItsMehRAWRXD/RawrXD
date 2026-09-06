// ============================================================================
// p1_ide_exec_policy_live_gguf_001.cpp — LIVE GGUF product-path gate
// Additive to APPLY_001. Does not reopen that seam cert.
// ============================================================================
#include "Deep2IDEIntegration.hpp"
#include "Deep2Engine.h"
#include "ElasticResidencyManager.hpp"
#include "execution_policy/ExecutionPolicy.hpp"
#include "execution_policy/ExecutionPolicyStore.hpp"
#include "execution_policy/ExecutionPolicyBridge.hpp"
#include "execution_policy/ExecutionPolicyApply.hpp"
#include "execution_policy/PolicyApply.hpp"
#include "execution_policy/PlacementPlan.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace fs = std::filesystem;
using namespace Deep2;
using namespace Deep2::Exec;

static int g_fail = 0;
#define PRED(name, cond)                                                       \
    do {                                                                       \
        const bool ok = !!(cond);                                              \
        std::printf("%-36s %s\n", name, ok ? "PASS" : "FAIL");                 \
        if (!ok) ++g_fail;                                                     \
    } while (0)

struct Census {
    size_t total = 0;
    size_t gpu0 = 0, gpu1 = 0, ram = 0, nvme = 0, hybrid = 0;
    size_t match = 0, mismatch = 0;
};

static std::string FindGguf(int argc, char** argv) {
    if (argc > 1 && fs::exists(argv[1])) return argv[1];
    if (const char* e = std::getenv("RAWRXD_TEST_GGUF"))
        if (e && *e && fs::exists(e)) return e;
    const char* cands[] = {
        "F:/~dev/tinyllama_fresh.gguf",
        "F:/~dev/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
        "D:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
        nullptr};
    for (int i = 0; cands[i]; ++i)
        if (fs::exists(cands[i])) return cands[i];
    return {};
}

static void WriteOutputs(const fs::path& dir, const PlacementApplyReport& rep,
                         const Census& c, const std::string& model,
                         const std::string& shaExpert, const std::string& shaAtSeam,
                         const std::string& shaAfter,
                         const std::string& firstFalse, bool allPass) {
    fs::create_directories(dir);
    {
        std::ofstream g(dir / "GATE.txt");
        g << "GATE=P1_IDE_EXEC_POLICY_LIVE_GGUF_001\n";
        g << "RESULT=" << (allPass ? "PASS" : "FAIL") << "\n";
        g << "FIRST_FALSE_TRANSITION=" << firstFalse << "\n";
        g << "MODEL=" << model << "\n";
        g << "POLICY_SHA_EXPERT=" << shaExpert << "\n";
        g << "POLICY_SHA_AT_SEAM=" << shaAtSeam << "\n";
        g << "POLICY_SHA_AFTER=" << shaAfter << "\n";
        g << "TOTAL_TENSORS=" << c.total << "\n";
        g << "PLACEMENT_MATCH=" << c.match << "\n";
        g << "PLACEMENT_MISMATCH=" << c.mismatch << "\n";
        g << "DETAIL=" << rep.detail << "\n";
    }
    {
        std::ofstream cfile(dir / "CENSUS.txt");
        cfile << "TOTAL_TENSORS       = " << c.total << "\n";
        cfile << "GPU0_PLANNED        = " << c.gpu0 << "\n";
        cfile << "GPU1_PLANNED        = " << c.gpu1 << "\n";
        cfile << "RAM_PLANNED         = " << c.ram << "\n";
        cfile << "NVME_PLANNED        = " << c.nvme << "\n";
        cfile << "HYBRID_PLANNED      = " << c.hybrid << "\n";
        cfile << "PLACEMENT_MATCH     = " << c.match << "\n";
        cfile << "PLACEMENT_MISMATCH  = " << c.mismatch << "\n";
    }
    {
        std::ofstream m(dir / "MISMATCHES.txt");
        for (const auto& o : rep.observations) {
            if (!o.match)
                m << o.name << " planned=" << (int)o.planned
                  << " observedGpu=" << o.observedGpu << "\n";
        }
    }
}

static Census BuildCensus(ElasticResidencyManager* elastic,
                          const ExecutionPolicy& policy,
                          PlacementApplyReport& rep) {
    Census c;
    if (!elastic) return c;
    auto names = elastic->ListTensorNames();
    c.total = names.size();
    rep.observations.clear();
    rep.mismatches = 0;
    for (const auto& name : names) {
        int layer = -1;
        if (name.rfind("blk.", 0) == 0)
            layer = std::atoi(name.c_str() + 4);
        DeviceKind planned = PlannedDeviceForTensor(policy, name, layer);
        const int stamped = elastic->GetPlannedGpu(name);
        ObservedPlacement obs;
        obs.name = name;
        obs.planned = planned;
        obs.observedGpu = stamped;
        switch (planned) {
        case DeviceKind::Gpu0: ++c.gpu0; obs.match = (stamped == 0); break;
        case DeviceKind::Gpu1: ++c.gpu1; obs.match = (stamped == 1); break;
        case DeviceKind::Host: ++c.ram; obs.match = (stamped < 0); break;
        case DeviceKind::Stream:
        case DeviceKind::Disk: ++c.nvme; obs.match = (stamped < 0); break;
        case DeviceKind::Hybrid: ++c.hybrid; obs.match = true; break;
        default: ++c.ram; obs.match = (stamped < 0); break;
        }
        if (obs.match) ++c.match;
        else {
            ++c.mismatch;
            ++rep.mismatches;
        }
        rep.observations.push_back(obs);
    }
    rep.observedTensors = c.total;
    rep.observedMatchesPlan = (c.total > 0 && c.mismatch == 0);
    return c;
}

static bool CallDeep2Load(const char* path, RawrXD::Deep2ModelLoader::LoadResult* out) {
    try {
        *out = RawrXD::Deep2ModelLoader::Load(path);
        if (!out->success && !out->error.empty())
            std::printf("LOAD_ERROR=%s\n", out->error.c_str());
        return out->success;
    } catch (const std::exception& e) {
        out->success = false;
        out->error = std::string("std::exception: ") + e.what();
        std::printf("LOAD_CXX=%s\n", e.what());
        return false;
    } catch (...) {
        out->success = false;
        out->error = "unknown C++ exception";
        std::printf("LOAD_CXX=unknown\n");
        return false;
    }
}

static bool LoadGgufSeh(const char* path,
                        RawrXD::Deep2ModelLoader::LoadResult* out,
                        unsigned long* sehCode) {
    *sehCode = 0;
    __try {
        return CallDeep2Load(path, out);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *sehCode = GetExceptionCode();
        out->success = false;
        out->error = "SEH during Deep2ModelLoader::Load";
        return false;
    }
}

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_IDE_EXEC_POLICY_LIVE_GGUF_001 ===\n");
    std::printf("NOTE: APPLY_001 remains PASS (seam). This gate is additive.\n");

    const std::string model = FindGguf(argc, argv);
    const fs::path ev = fs::path("evidence") / "P1_IDE_EXEC_POLICY_LIVE_GGUF_001";
    std::string firstFalse = "NONE";
    PlacementApplyReport rep{};
    Census census{};

    if (model.empty()) {
        PRED("GGUF_OPEN", false);
        firstFalse = "GGUF_OPEN";
        WriteOutputs(ev, rep, census, "(none)", "", "", "", firstFalse, false);
        std::printf("\nGATE FAIL — no GGUF (set RAWRXD_TEST_GGUF)\n");
        _Exit(2);
    }
    std::printf("MODEL=%s\n", model.c_str());

    EnsurePolicyLoaded();
    ExecutionPolicy expert = MakeDefaultPolicy();
    expert.mode = UiMode::Expert;
    expert.persistRuntimeChanges.force(false, SettingAuthority::Session,
                                       SettingMutability::Immediate);
    expert.placement.layerRanges.clear();
    expert.placement.layerRanges.push_back({LayerRange{0, 10}, DeviceKind::Gpu0});
    expert.placement.layerRanges.push_back({LayerRange{11, -1}, DeviceKind::Stream});
    expert.placement.embeddings.force(DeviceKind::Host, SettingAuthority::UserLocked,
                                      SettingMutability::TokenBoundary);
    expert.placement.lmHead.force(DeviceKind::Gpu0, SettingAuthority::UserLocked,
                                  SettingMutability::TokenBoundary);
    (void)ExecutionPolicyStore::Instance().apply(
        expert, SettingAuthority::Session, "LIVE_GGUF_001");

    const std::string shaBefore = PolicySha256(ActivePolicy());
    PRED("POLICY_LOADED_BEFORE_REGISTER", !shaBefore.empty());

    RawrXD::Deep2ModelLoader::LoadResult load{};
    unsigned long seh = 0;
    const bool opened = LoadGgufSeh(model.c_str(), &load, &seh);
    if (seh) {
        std::printf("GGUF_OPEN_SEH=0x%08lX\n", seh);
        load.error = "SEH 0x" + std::to_string(seh);
    }
    PRED("GGUF_OPEN", opened);
    if (!opened && firstFalse == "NONE") firstFalse = "GGUF_OPEN";

    PRED("GGUF_PARSE", opened && load.tensorCount > 0);
    if (opened && load.tensorCount == 0 && firstFalse == "NONE")
        firstFalse = "GGUF_PARSE";

    auto* elastic = RawrXD::Deep2ModelLoader::GetElastic();
    const size_t realTensors =
        elastic ? elastic->ListTensorNames().size() : 0;
    PRED("REAL_TENSOR_SET_NONZERO", realTensors > 0 && realTensors >= 8);
    if (!(realTensors > 0 && realTensors >= 8) && firstFalse == "NONE")
        firstFalse = "REAL_TENSOR_SET_NONZERO";

    const auto* last = RawrXD::Deep2ModelLoader::GetLastPolicyApplyReport();
    if (last) rep = *last;
    PRED("ENFORCE_SEAM_CALLED",
         last && last->policyLoaded && last->planDerived);
    if (!(last && last->policyLoaded && last->planDerived) &&
        firstFalse == "NONE")
        firstFalse = "ENFORCE_SEAM_CALLED";

    // Re-observe every real tensor (not the synthetic 4).
    if (elastic)
        census = BuildCensus(elastic, ActivePolicy(), rep);

    PRED("MARS_PLACEMENT_COMPLETED",
         census.total > 0 && census.match == census.total);
    if (!(census.total > 0 && census.match == census.total) &&
        firstFalse == "NONE")
        firstFalse = "MARS_PLACEMENT_COMPLETED";

    PRED("OBSERVED_PLACEMENT_MATCHES_PLAN",
         census.total > 0 && census.mismatch == 0 &&
             census.total == realTensors);
    if (!(census.total > 0 && census.mismatch == 0) && firstFalse == "NONE")
        firstFalse = "OBSERVED_PLACEMENT_MATCHES_PLAN";

    PRED("MODEL_READY", load.success && realTensors > 0);
    if (!(load.success && realTensors > 0) && firstFalse == "NONE")
        firstFalse = "MODEL_READY";

    // Policy SHA at certified IDE load seam (post EnforcePolicyOnIdeLoad). Generate
    // must not drift placement/budget fields from this anchor — not pre-load expert apply.
    const std::string shaAtSeam = PolicySha256(ActivePolicy());
    std::printf("POLICY_SHA_AT_SEAM=%s\n", shaAtSeam.c_str());

    bool genOk = false;
    if (load.success) {
        RawrXD::Deep2InferenceSession session;
        auto cfg = RawrXD::Deep2InferenceSession::SessionConfig::FromActivePolicy();
        cfg.maxContextLength = 256;
        if (session.Initialize(load, cfg)) {
            auto gr = session.Generate("ping");
            genOk = (gr.tokensGenerated > 0) || !gr.text.empty();
            if (!genOk)
                std::printf("GENERATE_DETAIL finish=%s tps=%.3f\n",
                            gr.finishReason.c_str(), gr.tokensPerSecond);
        } else {
            std::printf("GENERATE_DETAIL session.Initialize failed\n");
        }
    }
    PRED("GENERATE_COMPLETES", genOk);
    if (!genOk && firstFalse == "NONE") firstFalse = "GENERATE_COMPLETES";

    const std::string shaAfter = PolicySha256(ActivePolicy());
    const bool shaStable = (shaAtSeam == shaAfter && !shaAtSeam.empty());
    PRED("POLICY_SHA_UNCHANGED", shaStable);
    if (!shaStable && firstFalse == "NONE") {
        firstFalse = "POLICY_SHA_UNCHANGED";
        std::printf("POLICY_SHA_DRIFT seam=%s after=%s\n", shaAtSeam.c_str(),
                    shaAfter.c_str());
    }

    std::printf("\n--- CENSUS ---\n");
    std::printf("TOTAL_TENSORS       = %zu\n", census.total);
    std::printf("GPU0_PLANNED        = %zu\n", census.gpu0);
    std::printf("GPU1_PLANNED        = %zu\n", census.gpu1);
    std::printf("RAM_PLANNED         = %zu\n", census.ram);
    std::printf("NVME_PLANNED        = %zu\n", census.nvme);
    std::printf("PLACEMENT_MATCH     = %zu\n", census.match);
    std::printf("PLACEMENT_MISMATCH  = %zu\n", census.mismatch);

    const bool all = (g_fail == 0);
    WriteOutputs(ev, rep, census, model, shaBefore, shaAtSeam, shaAfter, firstFalse,
                 all);
    // Also write under repo evidence/ when cwd is build-ninja
    try {
        const fs::path repoEv =
            fs::path("F:/~dev/rawrxd/evidence") / "P1_IDE_EXEC_POLICY_LIVE_GGUF_001";
        WriteOutputs(repoEv, rep, census, model, shaBefore, shaAtSeam, shaAfter,
                     firstFalse, all);
    } catch (...) {
    }

    std::printf("\nGATE %s  FIRST_FALSE=%s\n", all ? "PASS" : "FAIL",
                firstFalse.c_str());
    RawrXD::Deep2ModelLoader::Unload();
    _Exit(all ? 0 : 1);
}
