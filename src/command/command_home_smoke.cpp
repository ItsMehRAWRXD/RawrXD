// ============================================================================
// command_home_smoke.cpp â€” headless ScreenPilot Command-home smoke (no Win32 GUI)
// ============================================================================
// Proves Desktop Preview failures without launching RawrXD-Win32IDE:
//   1) Session bind required
//   2) Steer lease does NOT permanently FAIL_CLOSED after a failed turn
//   3) LOCAL_ONLY fail-closed on ollama/:11434 steer text
//   4) Optional: RAWRXD_SMOKE_GGUF=<path> Deep2 load + generate
//
// Build:  ninja command_home_smoke
// Run:    .\bin\command_home_smoke.exe
//         $env:RAWRXD_SMOKE_GGUF='F:\path\to\model.gguf'; .\bin\command_home_smoke.exe
// ============================================================================

#include "CommandBroker.h"
#include "SessionBinder.h"
#include "../agents/SharedAgentWorkRegistry.hpp"
#include "../agentic/LocalOnlyPolicy.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#if defined(COMMAND_HOME_SMOKE_WITH_DEEP2)
#include "../runtime/IModelRuntime.hpp"
#endif

using RawrXD::Command::CommandBroker;
using RawrXD::Command::SessionBinder;
using RawrXD::Command::SessionSnapshot;

struct Check {
    const char* id = nullptr;
    bool pass = false;
    std::string detail;
};

static std::vector<Check> g_checks;

static void record(const char* id, bool pass, const std::string& detail) {
    g_checks.push_back(Check{id, pass, detail});
    std::printf("[%s] %s â€” %s\n", pass ? "PASS" : "FAIL", id, detail.c_str());
}

static void bindCanonicalSession() {
    SessionSnapshot snap;
    snap.machine = "smoke-host";
    snap.workspaceRoot = R"(F:\~dev\rawrxd)";
    snap.repository = "rawrxd";
    snap.branch = "main";
    snap.model = "Deep2 Local";
    snap.bound = true;
    SessionBinder::instance().bind(snap);
}

static int writeGate(bool allPass) {
#ifdef _WIN32
    CreateDirectoryA(R"(F:\~dev\rawrxd\evidence\COMMAND_HOME_SMOKE_001)", nullptr);
#endif
    const char* path = R"(F:\~dev\rawrxd\evidence\COMMAND_HOME_SMOKE_001\GATE.txt)";
    FILE* f = nullptr;
#ifdef _WIN32
    fopen_s(&f, path, "w");
#else
    f = std::fopen(path, "w");
#endif
    if (!f) {
        std::printf("[WARN] could not write %s\n", path);
        return allPass ? 0 : 1;
    }
    std::fprintf(f, "COMMAND_HOME_SMOKE_001\n");
    std::fprintf(f, "status=%s\n", allPass ? "PASS" : "FAIL");
    std::fprintf(f, "gui=none\n");
    for (const auto& c : g_checks) {
        std::fprintf(f, "%s=%s detail=%s\n", c.id, c.pass ? "PASS" : "FAIL", c.detail.c_str());
    }
    std::fclose(f);
    std::printf("Wrote %s\n", path);
    return allPass ? 0 : 1;
}

int main() {
    std::printf("=== COMMAND_HOME_SMOKE_001 (headless) ===\n");

    SessionBinder::instance().clear();
    CommandBroker::instance().setSteerHandler([](const std::string&, RawrXD::Command::SteerMode) {});
    auto unbound = CommandBroker::instance().steer("hello");
    record("STEER_UNBOUND", !unbound.ok && !unbound.text.empty(), unbound.text);

    bindCanonicalSession();
    int steerCalls = 0;
    CommandBroker::instance().setSteerHandler([&](const std::string& msg, RawrXD::Command::SteerMode) {
        ++steerCalls;
        (void)msg;
        // Mirror UI: failed/complete generation must idle and release lease.
        CommandBroker::instance().setAgentActive(false);
    });

    auto r1 = CommandBroker::instance().steer("test");
    record("STEER_1_OK", r1.ok, r1.ok ? "first steer accepted" : r1.text);

    auto r2 = CommandBroker::instance().steer("test-again");
    const bool leaseStuck =
        !r2.ok && r2.text.find("write lease held") != std::string::npos;
    record("STEER_2_NO_LEASE_STUCK", r2.ok && !leaseStuck,
           r2.ok ? "second steer accepted (lease released)" : r2.text);
    record("STEER_HANDLER_FIRED", steerCalls >= 2,
           "handler_calls=" + std::to_string(steerCalls));

    // Explicit stop must also clear any leftover lease.
    CommandBroker::instance().steer("third");
    CommandBroker::instance().stopAgent();
    auto r3 = CommandBroker::instance().steer("after-stop");
    record("STEER_AFTER_STOP", r3.ok, r3.ok ? "steer ok after stopAgent" : r3.text);

    auto bad = CommandBroker::instance().steer("please use ollama on :11434");
    const bool ollamaBlocked =
        bad.text.find("LOCAL_ONLY") != std::string::npos ||
        bad.text.find("FAIL_CLOSED") != std::string::npos ||
        bad.text.find(RawrXD::LocalOnly::kHardDiagnostic) != std::string::npos;
    record("STEER_OLLAMA_FAIL_CLOSED", ollamaBlocked,
           bad.text.empty() ? "(empty)" : bad.text);

#if defined(COMMAND_HOME_SMOKE_WITH_DEEP2)
    const char* gguf = std::getenv("RAWRXD_SMOKE_GGUF");
    if (gguf && gguf[0]) {
        std::printf("RAWRXD_SMOKE_GGUF=%s\n", gguf);
        std::string err;
        auto rt = RawrXD::Runtime::CreateModelRuntime("deep2");
        if (!rt) {
            record("DEEP2_RUNTIME_CREATE", false, "CreateModelRuntime(deep2) returned null");
        } else if (!rt->LoadModel(gguf, err)) {
            record("DEEP2_LOAD", false, err.empty() ? "LoadModel failed" : err);
        } else if (!rt->IsLoaded()) {
            record("DEEP2_LOAD", false, "LoadModel true but IsLoaded()=false");
        } else {
            record("DEEP2_LOAD", true, "model loaded");
            RawrXD::Runtime::GenerationRequest req;
            req.prompt = "[ScreenPilot Agent mode] Say hi in three words.";
            req.systemPrompt =
                "You are RawrXD ScreenPilot on the local machine. Answer concisely.";
            req.maxTokens = 32;
            req.temperature = 0.7f;
            auto result = rt->Generate(req);
            const bool ok = result.success && !result.text.empty() &&
                            result.errorMessage.find("Failed to start") == std::string::npos;
            record("DEEP2_GENERATE", ok,
                   ok ? ("text=" + result.text.substr(0, 80))
                      : (result.errorMessage.empty() ? "empty generation"
                                                     : result.errorMessage));
        }
    } else {
        record("DEEP2_GENERATE", true, "SKIPPED (set RAWRXD_SMOKE_GGUF to enable)");
    }
#else
    record("DEEP2_GENERATE", true, "SKIPPED (built without COMMAND_HOME_SMOKE_WITH_DEEP2)");
#endif

    bool all = true;
    for (const auto& c : g_checks) {
        if (!c.pass) all = false;
    }
    std::printf("=== %s (%zu checks) ===\n", all ? "PASS" : "FAIL", g_checks.size());
    return writeGate(all);
}
