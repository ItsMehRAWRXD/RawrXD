// IDE Test Runner - Comprehensive function testing with logging
// Tests every aspect of the RawrXD IDE
// Launches RawrXD-Win32IDE-Native.exe and tests its window via Win32 API

#include "IDETestAgent.h"
#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == (DWORD)lParam && IsWindowVisible(hwnd)) {
        *(HWND*)lParam = hwnd;  // Reuse lParam to return hwnd via pid trick won't work; use a struct instead
        return FALSE;
    }
    return TRUE;
}

int main(int argc, char* argv[]) {
    std::cout << "RawrXD IDE Test Runner\n";
    std::cout << "======================\n\n";

    // Parse command-line arguments
    bool headless = false;
    std::string outputPath = "RawrXD_IDE_TestResults.txt";
    std::string ideExePath;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--headless") {
            headless = true;
        } else if (arg == "--output" && i + 1 < argc) {
            outputPath = argv[++i];
        } else if (arg == "--ide" && i + 1 < argc) {
            ideExePath = argv[++i];
        }
    }

    if (ideExePath.empty()) {
        ideExePath = "F:\\rawrxd\\build_deep2_fix\\bin\\Release\\RawrXD-Win32IDE-Native.exe";
    }

    std::cout << "Step 1: Launching IDE: " << ideExePath << "\n";

    // Launch the IDE executable
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    if (!CreateProcessA(
            ideExePath.c_str(),
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_NEW_CONSOLE,
            NULL,
            NULL,
            &si,
            &pi)) {
        std::cerr << "ERROR: Failed to launch IDE executable: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "Step 2: IDE launched (PID: " << pi.dwProcessId << ")\n";

    // Wait for the IDE window to appear
    HWND hwndMain = NULL;
    const int maxWaitMs = 60000;
    const int intervalMs = 200;
    int elapsed = 0;

    while (elapsed < maxWaitMs) {
        // Enumerate windows to find our IDE's main window
        hwndMain = NULL;
        DWORD targetPid = pi.dwProcessId;

        // Use a struct to pass both PID and result
        struct FindCtx { DWORD pid; HWND hwnd; } ctx{ targetPid, NULL };

        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* ctx = (FindCtx*)lParam;
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
if (pid == ctx->pid && IsWindow(hwnd)) {
                    char className[256] = {0};
                    GetClassNameA(hwnd, className, sizeof(className));
                    LOG_DEBUG("Found window: pid=" + std::to_string(pid) + " class=" + className + " hwnd=" + std::to_string((uintptr_t)hwnd));
                    ctx->hwnd = hwnd;
                    return FALSE;
            }
            return TRUE;
        }, (LPARAM)&ctx);

        hwndMain = ctx.hwnd;
        if (hwndMain && IsWindow(hwndMain) && IsWindowVisible(hwndMain)) {
            break;
        }
        Sleep(intervalMs);
        elapsed += intervalMs;
    }

    if (!hwndMain) {
        std::cerr << "ERROR: IDE window did not appear within " << maxWaitMs << "ms\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    std::cout << "Step 3: IDE window found (HWND: " << (uintptr_t)hwndMain << ")\n";

    // Create test agent and run tests
    std::cout << "Step 4: Running comprehensive IDE tests...\n\n";
    IDETestAgent testAgent(hwndMain);
    testAgent.runAllTests(outputPath + ".hierarchy");

    // Get results
    const auto& results = testAgent.getResults();

    // Print results to console
    std::cout << "\n===========================================\n";
    std::cout << "Test Results Summary\n";
    std::cout << "===========================================\n";

    int passed = 0, failed = 0;
    for (const auto& result : results) {
        if (result.passed) {
            passed++;
            std::cout << " [PASS] " << result.testName << " (" << result.durationMs << "ms)\n";
        } else {
            failed++;
            std::cout << " [FAIL] " << result.testName << " - " << result.errorMessage << "\n";
        }
    }

    std::cout << "\nTotal: " << results.size() << " tests\n";
    std::cout << "Passed: " << passed << " (" << (results.size() > 0 ? (passed * 100 / results.size()) : 0) << "%)\n";
    std::cout << "Failed: " << failed << "\n";
    std::cout << "===========================================\n";

    // Write detailed results to file
    std::ofstream resultFile(outputPath);
    if (resultFile.is_open()) {
        resultFile << "RawrXD IDE Test Results\n";
        resultFile << "=======================\n\n";
        resultFile << "IDE Executable: " << ideExePath << "\n";
        resultFile << "Test Run Date: " << __DATE__ << " " << __TIME__ << "\n\n";

        for (const auto& result : results) {
            resultFile << (result.passed ? "[PASS] " : "[FAIL] ");
            resultFile << result.testName;
            resultFile << " (" << result.durationMs << "ms)";
            if (!result.passed) {
                resultFile << "\n  Error: " << result.errorMessage;
            }
            resultFile << "\n";
        }

        resultFile << "\nSummary:\n";
        resultFile << "Total: " << results.size() << "\n";
        resultFile << "Passed: " << passed << "\n";
        resultFile << "Failed: " << failed << "\n";
        resultFile.close();

        std::cout << "\nDetailed results written to: " << outputPath << "\n";
    }

    // Cleanup
    if (!headless) {
        std::cout << "\nPress Enter to close IDE and exit...\n";
        std::cin.get();
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (failed == 0) ? 0 : 1;
}
