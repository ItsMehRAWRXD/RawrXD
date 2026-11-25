// =============================================================================
// verify_buildrun_test.cpp — deterministic VerifyBuildRun certification.
// =============================================================================
// No model calls: uses the shared verification core with the PRODUCTION
// runner (RunProcess). Absolute source/exe paths; MSVC via buildPrefix.
// =============================================================================
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include "build_verify.h"
#include "process_runner.h"

using rawrxd::agentic::RunProcess;
using rawrxd::agentic::VerifyBuildRunWith;
using rawrxd::agentic::VerifyOutcome;

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    int failures = 0;
    const std::string dir = getenv("TEMP") ? getenv("TEMP") : ".";
    const std::string ws = dir + "\\vb_ws";
    std::filesystem::create_directories(ws);
    const std::string good = ws + "\\good.c";
    const std::string bad = ws + "\\bad.c";
    const std::string goodExe = ws + "\\good.exe";
    {
        std::ofstream(good) << "#include <stdio.h>\nint main(void){"
                               "printf(\"Hello from RawrXD\\n\");return 0;}\n";
        std::ofstream(bad) << "int main(void) { this is not valid C }\n";
    }
    const std::string vcvars =
        "call \"C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\"
        "BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat\" >nul 2>&1 && ";
    auto check = [&](const char* name, bool ok) {
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
        if (!ok) ++failures;
    };
    // 1. PASS.
    {
        std::remove(goodExe.c_str());
        const auto r = VerifyBuildRunWith(
            RunProcess, ws, "cl /nologo \"" + good + "\" /Fe\"" + goodExe +
                "\"", "\"" + goodExe + "\"", vcvars, "Hello from RawrXD");
        const bool exeFresh = std::filesystem::exists(goodExe);
        std::printf("[INFO] build=%d run=%d exe=%d\n", r.buildExit, r.runExit,
                    exeFresh ? 1 : 0);
        if (!r.verified())
            std::printf("[INFO] build_out: %s\nrun_out: %s\n",
                        r.buildOut.c_str(), r.runOut.c_str());
        check("pass.outcome", r.verified() && exeFresh);
    }
    // 2. BUILD_FAILURE.
    {
        const auto r = VerifyBuildRunWith(
            RunProcess, ws, "cl /nologo \"" + bad + "\" /Febad.exe", "bad.exe",
            vcvars, "Hello from RawrXD");
        check("build_failure.outcome",
              r.outcome == VerifyOutcome::BuildFailure);
    }
    // 3. OUTPUT_MISMATCH.
    {
        const auto r = VerifyBuildRunWith(
            RunProcess, ws, "cl /nologo \"" + good + "\" /Fe\"" + goodExe +
                "\"", "\"" + goodExe + "\"", vcvars, "NOT THE OUTPUT");
        check("mismatch.outcome",
              r.outcome == VerifyOutcome::OutputMismatch);
    }
    // 4. CAPTURE: run succeeds but produces no output.
    {
        const auto r = VerifyBuildRunWith(
            RunProcess, ws, "cl /nologo \"" + good + "\" /Fe\"" + goodExe +
                "\"", "cmd /c exit 0", vcvars, "Hello from RawrXD");
        check("capture.outcome",
              r.outcome == VerifyOutcome::CaptureFailure);
    }
    std::printf("VERIFY_BUILDRUN_TEST %s (failures=%d)\n",
                failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}