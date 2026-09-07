// rkc_negative_knowledge_cert.cpp — RKC_NEGATIVE_KNOWLEDGE_001
#include "rkc/RKCCompiler.hpp"
#include "rkc/RKCGapEngine.hpp"
#include "rkc/RKCNegativeKnowledge.hpp"
#include "rkc/RKCRecipes.hpp"
#include "rkc/RKCValidator.hpp"
#include "rkc/RKCWorld.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace RawrXD::RKC;
namespace fs = std::filesystem;

int main() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RKC_NEGATIVE_KNOWLEDGE_001",
                     nullptr);
#endif
    const char* rootEnv = std::getenv("DEEP2_REPO_ROOT");
    std::string root = rootEnv && rootEnv[0] ? rootEnv : "G:\\~dev\\rawrxd";
    printf("RKC_NEGATIVE_KNOWLEDGE_001\nREPO=%s\n", root.c_str());

    World world;
    world.clearSession();
    WorldObserveConfig cfg;
    cfg.modelPath = ""; // missing model
    cfg.availableVram = 0;
    cfg.weightsBytes = 0;
    cfg.probeOllama11434 = true;
    world.observeHardware(cfg);
    world.observeLivePath();
    auto st = ObserveAbsenceCatalog(world, cfg, root);
    ApplyRecipes(world, Deep2RecipePack());

    printf("ABSENCE atoms=%u kinds=%u NP=%u NR=%u NO=%u NS=%u NC=%u NA=%u\n",
           st.atoms, st.kindsPresent, st.notPresent, st.notReachable,
           st.notObserved, st.notSupported, st.notConnected, st.notActive);

    const bool kindsOk = st.kindsPresent >= 5 && st.atoms >= 5 &&
                         st.notPresent > 0 && st.notReachable > 0 &&
                         st.notObserved > 0 && st.notSupported > 0 &&
                         (st.notConnected > 0 || st.notActive > 0);

    // Absence must not become inferred success.
    const auto* mc = world.get("model_complete");
    const bool noFalseComplete =
        !mc || mc->value != "1" || mc->state != EpistemicState::Derived;

    const bool negToDerived =
        !TryPromote(EpistemicState::NotPresent, EpistemicState::Derived, false).ok;
    const bool negToReal =
        !TryPromote(EpistemicState::NotPresent, EpistemicState::Real, false).ok;
    const bool negToRealObs =
        !TryPromote(EpistemicState::NotPresent, EpistemicState::Real, true).ok;
    const bool notObsCanFill =
        TryPromote(EpistemicState::NotObserved, EpistemicState::Real, true).ok;

    CompiledGoal goal = CompileGoal(
        "Can Deep2 execute this model entirely locally?");
    GapResult gap = ResolveGaps(world, goal);
    bool negInProof = !gap.proof.negative.empty();
    bool knownHasModelExistsSuccess = false;
    for (const auto& a : gap.proof.known) {
        if (a.key == "model_exists" && a.value == "1")
            knownHasModelExistsSuccess = true;
    }

    printf("KINDS=%d NO_FALSE_COMPLETE=%d NEG_TO_DERIVED_BLOCKED=%d "
           "NEG_TO_REAL_BLOCKED=%d NOT_OBS_FILL=%d PROOF_NEG=%d "
           "NO_KNOWN_MODEL=%d\n",
           kindsOk ? 1 : 0, noFalseComplete ? 1 : 0, negToDerived ? 1 : 0,
           (negToReal && negToRealObs) ? 1 : 0, notObsCanFill ? 1 : 0,
           negInProof ? 1 : 0, !knownHasModelExistsSuccess ? 1 : 0);

    const bool pass = kindsOk && noFalseComplete && negToDerived && negToReal &&
                      negToRealObs && notObsCanFill && negInProof &&
                      !knownHasModelExistsSuccess;
    printf("RKC_NEGATIVE_KNOWLEDGE_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\RKC_NEGATIVE_KNOWLEDGE_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "atoms=%u kinds=%u\n", st.atoms, st.kindsPresent);
        fprintf(f, "NP=%u NR=%u NO=%u NS=%u NC=%u NA=%u\n", st.notPresent,
                st.notReachable, st.notObserved, st.notSupported,
                st.notConnected, st.notActive);
        fprintf(f, "proof_neg=%zu known=%zu missing=%zu\n",
                gap.proof.negative.size(), gap.proof.known.size(),
                gap.proof.missing.size());
        fprintf(f, "RKC_NEGATIVE_KNOWLEDGE_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    return pass ? 0 : 2;
}
