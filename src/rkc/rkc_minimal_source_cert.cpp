// rkc_minimal_source_cert.cpp — RKC_MINIMAL_SOURCE_001
#include "rkc/RKCCodeWorld.hpp"
#include "rkc/RKCMinimalSource.hpp"
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
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RKC_MINIMAL_SOURCE_001", nullptr);
#endif
    const char* rootEnv = std::getenv("DEEP2_REPO_ROOT");
    std::string root = rootEnv && rootEnv[0] ? rootEnv : "G:\\~dev\\rawrxd";
    printf("RKC_MINIMAL_SOURCE_001\nREPO=%s\n", root.c_str());
    if (!fs::is_directory(root + "/src/deep2")) {
        printf("RKC_MINIMAL_SOURCE_001=SKIP\n"); return 0;
    }

    const char* query = "fix GPU fallback";
    World world;
    world.clearSession();
    (void)ObserveCodeWorld(world, root);
    ObserveGpuFallbackPack(world, root);
    auto sel = SelectMinimalSource(world, query, root);
    fputs(sel.emit.c_str(), stdout);

    const bool hasDispatch =
        sel.emit.find("DispatchGemvDevice") != std::string::npos;
    const bool hasCaller =
        sel.emit.find("Deep2Engine_GpuForward.cpp") != std::string::npos;
    const bool hasState =
        sel.emit.find("Deep2Engine.h") != std::string::npos;
    const bool lean =
        sel.filesRkc > 0 && sel.filesRkc <= 5 &&
        sel.filesNaive >= 8 &&
        sel.bytesRkc > 0 && sel.bytesNaive > sel.bytesRkc &&
        sel.bytesRkc * 4 < sel.bytesNaive; // <25% of naive
    const bool irrelevant = sel.irrelevantFiles > 0;
    const bool noDump =
        sel.emit.find("## Open:") == std::string::npos &&
        sel.emit.find("whole repository") == std::string::npos;

    printf("HAS_DISPATCH=%d HAS_CALLER=%d HAS_STATE=%d LEAN=%d IRR=%d\n",
           hasDispatch ? 1 : 0, hasCaller ? 1 : 0, hasState ? 1 : 0,
           lean ? 1 : 0, irrelevant ? 1 : 0);
    printf("BYTES_RKC=%llu BYTES_NAIVE=%llu RATIO=%.3f\n",
           (unsigned long long)sel.bytesRkc,
           (unsigned long long)sel.bytesNaive,
           sel.bytesNaive ? (double)sel.bytesRkc / (double)sel.bytesNaive : 0.0);

    const bool pass =
        hasDispatch && hasCaller && hasState && lean && irrelevant && noDump &&
        sel.goalKey == "fix_gpu_fallback";
    printf("RKC_MINIMAL_SOURCE_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\RKC_MINIMAL_SOURCE_001\\GATE_STATUS.txt", "w");
    if (f) {
        fputs(sel.emit.c_str(), f);
        fprintf(f, "RKC_MINIMAL_SOURCE_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    return pass ? 0 : 2;
}
