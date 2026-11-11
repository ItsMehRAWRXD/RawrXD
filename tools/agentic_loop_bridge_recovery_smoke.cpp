#include "Win32IDE_AgenticLoopBridge.h"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

namespace
{
bool RunMissingHelperCase(AgenticLoopBridge& bridge, const std::string& workdir,
                          int ordinal)
{
    AgenticLoopBridge::TaskConfig cfg;
    cfg.provider = "local";
    cfg.modelPath = "missing-test-model.gguf";
    cfg.workDir = workdir;
    cfg.targetFile = "fixture.cpp";
    cfg.task = "This negative-control case must fail before model execution.";
    cfg.maxWallTimeSec = 2;

    bool started = false;
    bool completed = false;
    bool success = true;
    std::string summary;
    started = bridge.StartTask(
        cfg,
        [](const std::string&) {},
        [](const AgenticLoopBridge::ToolResult&) {},
        [&](bool ok, const std::string& text) {
            completed = true;
            success = ok;
            summary = text;
        });

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(10);
    while (!completed && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));

    const bool passed = started && completed && !success &&
                        summary.find("executable not found") != std::string::npos;
    std::cout << "BRIDGE_MISSING_HELPER_CASE=" << ordinal << " "
              << (passed ? "PASS" : "FAIL") << "\n";
    return passed;
}

bool RunTimeoutCase(AgenticLoopBridge& bridge)
{
    AgenticLoopBridge::TaskConfig cfg;
    cfg.provider = "local";
    cfg.modelPath = "timeout-test-model.gguf";
    cfg.workDir = (std::filesystem::current_path().parent_path() /
                   "bridge_smoke_timeout").string();
    cfg.targetFile = "fixture.cpp";
    cfg.task = "The helper intentionally exceeds the host wall budget.";
    cfg.maxWallTimeSec = 1;

    bool completed = false;
    bool success = true;
    std::string summary;
    const bool started = bridge.StartTask(
        cfg,
        [](const std::string&) {},
        [](const AgenticLoopBridge::ToolResult&) {},
        [&](bool ok, const std::string& text) {
            completed = true;
            success = ok;
            summary = text;
        });

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(10);
    while (!completed && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));

    const bool passed = started && completed && !success &&
                        summary.find("timeout") != std::string::npos;
    std::cout << "BRIDGE_TIMEOUT_CASE=" << (passed ? "PASS" : "FAIL") << "\n";
    return passed;
}
}

int main()
{
    // This executable is emitted into a directory that intentionally has no
    // deep2_agentic_loop.exe sibling.  The bridge must report a bounded,
    // recoverable failure and remain reusable for the second attempt.
    const std::string workdir = ".";
    AgenticLoopBridge bridge(nullptr);
    const bool first = RunMissingHelperCase(bridge, workdir, 1);
    const bool second = RunMissingHelperCase(bridge, workdir, 2);
    const bool timeout = RunTimeoutCase(bridge);
    const bool afterTimeout = RunMissingHelperCase(bridge, workdir, 3);
    const bool pass = first && second && timeout && afterTimeout && !bridge.IsRunning();
    std::cout << "BRIDGE_RECOVERY_SMOKE " << (pass ? "PASS" : "FAIL") << "\n";
    return pass ? 0 : 1;
}
