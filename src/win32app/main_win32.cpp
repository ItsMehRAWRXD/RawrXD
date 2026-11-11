#include "Win32IDE.h"
#include "IDELogger.h"
#include "ProductionRuntime.hpp"
#include <windows.h>
#include <exception>
#include <iostream>
#include <string>
#include <fstream>
#include <shlobj.h>
#include <filesystem>

static std::string GetLogPath() {
    std::string logDir;
    PWSTR path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path))) {
        logDir = (std::filesystem::path(path) / "RawrXD" / "logs").string();
        CoTaskMemFree(path);
    } else {
        char localAppData[MAX_PATH];
        if (GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH)) {
            logDir = (std::filesystem::path(localAppData) / "RawrXD" / "logs").string();
        } else {
            logDir = "C:\\RawrXD_logs";
        }
    }
    std::filesystem::create_directories(logDir);
    return logDir + "\\RawrXD_IDE.log";
}

namespace {

/// `--health-check` / `--health-check-json`: answers the process health probes
/// without starting the GUI. This is the supported entry point for supervisors
/// and CI, so they do not need a window manager or an interactive session to
/// observe us.
int RunHealthCheckProbe(const std::string& flag) {
    using namespace Sovereign::Production;
    try {
        ProductionRuntime::Options options;
        // A probe reports state; it must not gate and must not install a
        // global exception filter just to answer a question.
        options.enforce_gates = false;
        options.install_signal_handlers = false;
        ProductionRuntime::init(options);
        HealthRegistry::instance().run_all();
        const bool ready = ProductionRuntime::probe_readiness();
        const std::string detail = HealthRegistry::instance().to_json(true);
        const bool live = ProductionRuntime::probe_liveness();

        if (flag == "--health-check-json") {
            std::cout << detail << std::endl;
        } else {
            std::cout << HealthRegistry::instance().probe_body()
                      << " (ready=" << (ready ? "true" : "false") << ")\n";
        }
        if (!live || !ready) std::cerr << detail << std::endl;
        ProductionRuntime::shutdown();
        return (live && ready) ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "health check failed: " << e.what() << std::endl;
        ProductionRuntime::shutdown();
        return 2;
    }
}

} // namespace

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Operational probe requested before any UI work, so a supervisor can
    // observe process state in a headless environment.
    if (__argc >= 2) {
        const std::string arg = __argv[1];
        if (arg == "--health-check" || arg == "--health-check-json") {
            return RunHealthCheckProbe(arg.c_str());
        }
    }

    // Initialize logger early
    try {
        IDELogger::getInstance().initialize(GetLogPath());
        IDELogger::getInstance().setLevel(IDELogger::Level::DEBUG);
        LOG_INFO("WinMain started - RawrXD Win32 IDE initializing");
    } catch (...) {
        // Fallback to file diagnostic if logger fails
        std::string fallbackPath = GetLogPath() + ".fallback";
        std::ofstream errLog(fallbackPath);
        errLog << "Logger initialization threw exception" << std::endl;
        errLog.close();
    }

    // Production-hardening runtime: configuration, structured logging,
    // metrics, tracing, security (encryption + audit) and readiness gates.
    // init() is what blocks startup on an unhealthy configuration rather than
    // letting the GUI come up in a state nobody can diagnose.
    Sovereign::Production::ProductionRuntime::Options options;
    options.enforce_gates = true;
    options.install_signal_handlers = true;
    if (!Sovereign::Production::ProductionRuntime::init(options)) {
        // A readiness gate failure is normally fatal: an operator must be able
        // to see why. RAWRXD_FAIL_FAST_GATES=false opts into degraded startup.
        LOG_ERROR("Readiness gates blocked startup; see the structured log");
        const std::string readiness_report =
            Sovereign::Production::ReadinessRunner::instance().run().summary();
        const std::string startup_error =
            "RawrXD refused to start because a readiness gate failed.\n\n" +
            readiness_report + "\n\nSee the structured log for details.";
        MessageBoxA(nullptr, startup_error.c_str(), "RawrXD startup blocked",
                    MB_OK | MB_ICONERROR);
        Sovereign::Production::ProductionRuntime::shutdown();
        return 3;
    }

    LOG_DEBUG("Creating Win32IDE instance");
    Win32IDE ide(hInstance);
    LOG_DEBUG("Win32IDE constructor completed");

    Sovereign::Production::AuditLogger::instance().append(
        "system", "ide.started", "RawrXD-IDE", "success");

    if (!ide.createWindow()) {
        LOG_ERROR("createWindow() failed");
        Sovereign::Production::AuditLogger::instance().append(
            "system", "ide.window_failed", "RawrXD-IDE", "failure");
        MessageBoxA(nullptr, "Failed to create window", "Error", MB_OK | MB_ICONERROR);
        Sovereign::Production::ProductionRuntime::shutdown();
        return 1;
    }

    LOG_INFO("Main window created successfully");
    ide.showWindow();
    LOG_INFO("Entering message loop");
    int rc = ide.runMessageLoop();
    LOG_INFO("Message loop exited with code " + std::to_string(rc));

    Sovereign::Production::AuditLogger::instance().append(
        "system", "ide.exit", "RawrXD-IDE", "success",
        "exit_code=" + std::to_string(rc));
    // Ordered shutdown: release IDE resources first, then the hardened runtime
    // that was still collecting metrics while the message loop ran.
    Sovereign::Production::ProductionRuntime::shutdown();
    return rc;
}
