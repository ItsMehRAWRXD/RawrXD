// certs/rawrxd_auto_ladder_001.cpp — U07
#include "../src/cli/rawr_safety_policy.hpp"
#include "../src/cli/rawr_permission_gate.hpp"
#include "../src/cli/rawr_destructive_action_guard.hpp"
#include "../src/cli/tools/rawr_patch_tool.hpp"
#include "../src/cli/tools/rawr_file_tool.hpp"
#include "../src/cli/tools/rawr_build_tool.hpp"
#include <cstdio>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

int main() {
    using namespace rawr;
    const std::string ws = "G:\\~dev\\rawrxd";
    const std::string path =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_UNLOCK_15\\auto_probe.txt";
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_UNLOCK_15",
                     nullptr);
#endif
    PatchEngine::WriteAll(path, "v0\n");

    SafetyPolicy off{};
    off.level = AutonomyLevel::Off;
    std::string out;
    if (ToolReadFile(off, ws, path, out)) {
        puts("RAWRXD_AUTO_LADDER_001=FAIL");
        return 1;
    }

    SafetyPolicy read{};
    read.level = AutonomyLevel::Read;
    if (!ToolReadFile(read, ws, path, out)) {
        puts("RAWRXD_AUTO_LADDER_001=FAIL");
        return 1;
    }
    PatchEngine eng;
    PatchRecord rec{};
    if (ToolApplyPatch(read, eng, ws, path, "v1\n", rec)) {
        puts("RAWRXD_AUTO_LADDER_001=FAIL");
        return 1;
    }

    SafetyPolicy patch{};
    patch.level = AutonomyLevel::Patch;
    if (!ToolApplyPatch(patch, eng, ws, path, "v1\n", rec)) {
        puts("RAWRXD_AUTO_LADDER_001=FAIL");
        return 1;
    }
    if (ToolRunBuild(patch, "cmd /c echo x") != -1) {
        puts("RAWRXD_AUTO_LADDER_001=FAIL");
        return 1;
    }

    SafetyPolicy build{};
    build.level = AutonomyLevel::Build;
    if (ToolRunBuild(build, "cmd /c echo auto_ladder_ok") != 0) {
        puts("RAWRXD_AUTO_LADDER_001=FAIL");
        return 1;
    }
    if (!DestructiveBlocked(build, "git push")) {
        puts("RAWRXD_AUTO_LADDER_001=FAIL");
        return 1;
    }

#ifdef _WIN32
    FILE* gf = nullptr;
    fopen_s(&gf,
            "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_UNLOCK_15\\GATE.txt",
            "w");
    if (gf) {
        fprintf(gf, "RAWRXD_AUTO_LADDER_001=PASS\n");
        fclose(gf);
    }
#endif
    puts("RAWRXD_AUTO_LADDER_001=PASS");
    return 0;
}
