// =============================================================================
// data_breakpoint_test.cpp — D5 live hardware data breakpoint acceptance.
// =============================================================================
// Launches the d5_debuggee, arms a DR0 write breakpoint on g_watched, and
// requires the backend to pause with stopReason data:0x... before the
// debuggee exits.
// =============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>

#include "win32app/Win32NativeDebugBackend.h"

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    const std::string exe = argc > 1 ? argv[1] : "d5_debuggee.exe";
    int failures = 0;

    rawrxd::Win32NativeDebugBackend backend;
    bool dataHit = false;
    std::string hitReason;
    uint64_t watchAddr = 0;
    backend.setStateCallback([&](const rawrxd::NativeDebugSnapshot& s) {
        if (s.stopReason.rfind("data:", 0) == 0) {
            dataHit = true;
            hitReason = s.stopReason;
        }
    });
    backend.setOutputCallback([&](const std::string& text) {
        std::printf("[dbg] %s", text.c_str());
    });

    // Arm the export breakpoint BEFORE launch: the backend preserves
    // deferred (address==0) export BPs across launch and applies them when
    // the image resolves, so the debuggee pauses at main.
    backend.addBreakpointExport("main");

    std::remove("d5_watch_addr.txt");  // before launch; the ctor writes it
    if (!backend.launch(exe)) {
        std::printf("[FAIL] launch failed\n");
        return 1;
    }
    // Wait for the initial breakpoint + the debuggee's address file.
    for (int i = 0; i < 100 && watchAddr == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::ifstream addrFile("d5_watch_addr.txt");
        if (addrFile) {
            std::string line;
            std::getline(addrFile, line);
            watchAddr = std::strtoull(line.c_str(), nullptr, 16);
        }
        if (watchAddr == 0) backend.continueExecution();
    }
    if (watchAddr == 0) {
        std::printf("[FAIL] debuggee never printed WATCH_ADDR\n");
        backend.stop(true);
        return 1;
    }
    std::printf("[INFO] watch address 0x%llx\n",
                (unsigned long long)watchAddr);
    std::remove("d5_loop_marker.txt");
    if (!backend.addDataBreakpointAddress(watchAddr, 4, "g_watched")) {
        std::printf("[FAIL] addDataBreakpointAddress refused\n");
        ++failures;
    }
    // Continue until the data stop or process exit.
    for (int i = 0; i < 200 && !dataHit; ++i) {
        backend.continueExecution();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (!backend.isActive()) break;
    }
    if (dataHit) {
        std::printf("[PASS] data breakpoint hit: %s\n", hitReason.c_str());
    } else {
        std::printf("[FAIL] data breakpoint never hit\n");
        ++failures;
    }
    // Did the debuggee's loop actually run under the debugger?
    std::ifstream marker("d5_loop_marker.txt");
    if (marker) {
        std::printf("[INFO] loop marker present (debuggee executed)\n");
    } else {
        std::printf("[INFO] loop marker absent (debuggee did not reach loop)\n");
    }
    backend.stop(true);
    std::printf("DATA_BREAKPOINT_TEST %s (failures=%d)\n",
                failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}