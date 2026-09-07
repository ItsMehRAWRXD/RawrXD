// rkc_code_world_cert.cpp — RKC_CODE_WORLD_001
#include "rkc/RKCCodeWorld.hpp"
#include "rkc/RKCValidator.hpp"
#include "rkc/RKCWorld.hpp"
#include "rkc/RKC.h"
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

static const KnowledgeAtom* Get(const World& w, const char* k) {
    return w.get(k);
}

int main() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RKC_CODE_WORLD_001", nullptr);
#endif
    const char* rootEnv = std::getenv("DEEP2_REPO_ROOT");
    std::string root = rootEnv && rootEnv[0] ? rootEnv : "G:\\~dev\\rawrxd";
    printf("RKC_CODE_WORLD_001\nREPO=%s\n", root.c_str());
    if (!fs::is_directory(root + "/src/deep2")) {
        printf("RKC_CODE_WORLD_001=SKIP\n"); return 0;
    }

    World world;
    world.clearSession();
    auto st = ObserveCodeWorld(world, root);
    printf("FILES=%u SYMBOLS=%u CALL_EDGES=%u REACH=%u NOT_REACH=%u\n",
           st.files, st.symbols, st.callEdges, st.reachable, st.notReachable);
    printf("GRAPH_NODES=%zu GRAPH_EDGES=%zu\n",
           world.graph().nodeCount(), world.graph().edges().size());

    const auto* begin =
        Get(world, "symbol_reachable_from_generate.LivePath_BeginGenerate");
    const auto* pol =
        Get(world, "symbol_reachable_from_generate.K2LivePolicy_Apply");
    const auto* fake =
        Get(world, "symbol_reachable_from_generate.FakeRemoteInfer");
    const auto* stream =
        Get(world, "symbol_reachable_from_stream.LivePath_BeginGenerate");
    const auto* fakeDef = Get(world, "symbol_defined.FakeRemoteInfer");

    const bool reachOk =
        begin && begin->state == EpistemicState::Derived && begin->value == "1" &&
        pol && pol->state == EpistemicState::Derived && pol->value == "1" &&
        stream && stream->state == EpistemicState::Derived && stream->value == "1";
    const bool negOk =
        fake && fake->state == EpistemicState::NotReachable &&
        fakeDef && fakeDef->state == EpistemicState::NotPresent;
    const bool counts =
        st.files >= 3 && st.symbols >= 5 && st.callEdges >= 4 &&
        world.graph().nodeCount() >= 8 && world.graph().edges().size() >= 4;
    const bool epistemic = RKC_VerifyNoSyntheticToReal() == 1;
    const bool noSynReal =
        !TryPromote(EpistemicState::Synthetic, EpistemicState::Real, true).ok;

    printf("REACH_LIVE=%d NEG_FAKE=%d COUNTS=%d NO_SYN_REAL=%d EPISTEMIC=%d\n",
           reachOk ? 1 : 0, negOk ? 1 : 0, counts ? 1 : 0, noSynReal ? 1 : 0,
           epistemic ? 1 : 0);

    const bool pass = reachOk && negOk && counts && noSynReal && epistemic;
    printf("RKC_CODE_WORLD_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\RKC_CODE_WORLD_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "FILES=%u SYMBOLS=%u EDGES=%u\n", st.files, st.symbols,
                st.callEdges);
        fprintf(f, "REACH_LIVE=%d NEG_FAKE=%d\n", reachOk ? 1 : 0, negOk ? 1 : 0);
        fprintf(f, "RKC_CODE_WORLD_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    return pass ? 0 : 2;
}
