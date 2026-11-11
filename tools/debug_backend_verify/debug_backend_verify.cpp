// Headless verification of Win32NativeDebugBackend (WaitForDebugEvent).
// PROMOTE=0 — prints measured gates; does not invent PASS.

#include "Win32NativeDebugBackend.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>

using rawrxd::NativeDebugSnapshot;
using rawrxd::NativeDebugState;
using rawrxd::Win32NativeDebugBackend;

static std::atomic<int> g_bpHits{0};
static std::atomic<int> g_steps{0};
static std::atomic<int> g_exits{0};
static std::string g_lastBp;
static std::string g_watchAtBp;
static std::mutex g_logMu;

static void logLine(const std::string& s) {
    std::lock_guard<std::mutex> lock(g_logMu);
    std::printf("%s\n", s.c_str());
    std::fflush(stdout);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: debug_backend_verify <debuggee.exe>\n");
        return 2;
    }
    const std::string exe = argv[1];
    Win32NativeDebugBackend dbg;
    std::atomic<bool> paused{false};
    NativeDebugSnapshot last{};

    dbg.setOutputCallback([](const std::string& s) { logLine(s); });
    dbg.setStateCallback([&](const NativeDebugSnapshot& s) {
        last = s;
        logLine(std::string("[state] ") + s.stopReason +
                " state=" + std::to_string(static_cast<int>(s.state)));
        if (s.stopReason.rfind("breakpoint:", 0) == 0) {
            g_bpHits.fetch_add(1);
            g_lastBp = s.stopReason;
            auto it = s.variables.find("g_watch_value");
            if (it != s.variables.end()) {
                g_watchAtBp = it->second;
            }
            paused.store(true);
        } else if (s.stopReason == "step") {
            g_steps.fetch_add(1);
            paused.store(true);
        } else if (s.state == NativeDebugState::Terminated) {
            g_exits.fetch_add(1);
            paused.store(false);
        }
    });

    if (!dbg.addBreakpointExport("break_site")) {
        logLine("FAIL addBreakpointExport");
        return 3;
    }
    if (!dbg.launch(exe)) {
        logLine("FAIL launch");
        return 4;
    }

    // Wait for first BP
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (!paused.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    const int bp1 = g_bpHits.load();
    std::string watch1 = g_watchAtBp;
    std::string eval;
    dbg.evaluateExpression("g_watch_value", eval);

    bool stepOk = false;
    if (bp1 >= 1) {
        stepOk = dbg.stepInto();
        paused.store(false);
        while (!paused.load() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    const int steps = g_steps.load();

    bool contOk = false;
    if (dbg.state() == NativeDebugState::Paused) {
        contOk = dbg.continueExecution();
        paused.store(false);
    }

    // Wait for exit (second BP may fire — continue through)
    auto exitDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (dbg.state() != NativeDebugState::Terminated &&
           std::chrono::steady_clock::now() < exitDeadline) {
        if (dbg.state() == NativeDebugState::Paused) {
            dbg.continueExecution();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    const DWORD exitCode = dbg.lastExitCode();
    dbg.stop(true);

    const bool bpPass = bp1 >= 1 && g_lastBp.find("break_site") != std::string::npos;
    const bool varPass = (!watch1.empty() && watch1 != "<unevaluable>") ||
                         (!eval.empty() && eval.find("<unevaluable>") == std::string::npos);
    const bool stepPass = stepOk && steps >= 1;
    const bool contPass = contOk;
    const bool exitPass = (exitCode == 7);

    std::printf("\n=== DEBUG_BACKEND_VERIFY ===\n");
    std::printf("BACKEND=WAITFORDEBUGEVENT\n");
    std::printf("CREATEPROCESS_DEBUG=1\n");
    std::printf("BP_HIT=%s hits=%d reason=%s\n", bpPass ? "1" : "0", bp1, g_lastBp.c_str());
    std::printf("VAR_INSPECT=%s watch=%s eval=%s\n", varPass ? "1" : "0", watch1.c_str(),
                eval.c_str());
    std::printf("STEP=%s steps=%d\n", stepPass ? "1" : "0", steps);
    std::printf("CONTINUE=%s\n", contPass ? "1" : "0");
    std::printf("EXIT_CODE=%lu expected=7 pass=%s\n", static_cast<unsigned long>(exitCode),
                exitPass ? "1" : "0");
    std::printf("SESSION_REAL=%s\n",
                (bpPass && varPass && stepPass && contPass && exitPass) ? "1" : "0");
    std::printf("PROMOTE=0 CERTIFIED=0 INVENT_PASS=0\n");

    const int rc = (bpPass && varPass && stepPass && contPass && exitPass) ? 0 : 1;
    std::printf("VERIFY_RC=%d\n", rc);
    return rc;
}
