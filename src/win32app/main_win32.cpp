#include "Win32IDE.h"
#include "IDELogger.h"
#include "Win32TerminalManager.h"
#include <windows.h>
#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#if defined(RAWRXD_NATIVE_IDE_EXT) && RAWRXD_NATIVE_IDE_EXT
#include "Win32IDE_ExtHostWire.h"
#endif

namespace {
void startupTrace(const char* message)
{
    std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
    if (trace) trace << message << '\n';
}

// SEH-only wrapper: noinline + no C++ objects in this frame (MSVC C2712/C2713).
// Do not call startupTrace (ofstream) from inside __try — inlining mixes EH forms.
#if defined(_MSC_VER)
__declspec(noinline) static int stopTerminalSeh(Win32TerminalManager* term)
{
    if (!term) return 0;
    __try {
        term->stop();
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}
#endif

// Product ConPTY smoke: exercises Win32TerminalManager start/write/drain.
// Writes oneshot receipt; --term-quit ExitProcess before ConPTY dtor/stop.
int runTermSmoke(const char* lpCmdLine)
{
    const char* receiptPath =
        "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\artifacts\\term_smoke_receipt.txt";
    startupTrace("runTermSmoke entered");
    try {
        std::mutex mu;
        std::string out;
        std::atomic<bool> finished{false};
        int exitCode = -1;

        Win32TerminalManager term;
        term.onOutput = [&](const std::string& chunk) {
            std::lock_guard<std::mutex> lk(mu);
            out += chunk;
        };
        term.onError = [&](const std::string& chunk) {
            std::lock_guard<std::mutex> lk(mu);
            out += chunk;
        };
        term.onFinished = [&](int code) {
            exitCode = code;
            finished = true;
        };

        startupTrace("runTermSmoke before start");
        const bool started = term.start(Win32TerminalManager::PowerShell);
        const auto transport = term.transport();
        const DWORD livePid = started ? term.pid() : 0;
        const char* transportName =
            transport == Win32TerminalManager::TransportConPTY ? "CONPTY" :
            transport == Win32TerminalManager::TransportPipe ? "PIPE" : "NONE";
        startupTrace(started ? "runTermSmoke start OK" : "runTermSmoke start FAIL");

        if (started) {
            // Interactive ConPTY expects CR. Keep smoke minimal + measurable.
            term.writeInput("Write-Output ONESHOT_CONPTY_ALIVE\r\n");
            for (int i = 0; i < 40; ++i) {
                {
                    std::lock_guard<std::mutex> lk(mu);
                    if (out.find("ONESHOT_CONPTY_ALIVE") != std::string::npos) break;
                }
                if (finished) break;
                Sleep(250);
            }
        }

        std::string captured;
        {
            std::lock_guard<std::mutex> lk(mu);
            captured = out;
        }
        const bool alive = captured.find("ONESHOT_CONPTY_ALIVE") != std::string::npos;
        const bool conpty = transport == Win32TerminalManager::TransportConPTY;

        // Write receipt BEFORE stop so a ConPTY teardown crash still leaves
        // measurable START/CONPTY/ALIVE evidence for the harness.
        CreateDirectoryA(
            "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\artifacts", nullptr);
        std::ofstream rec(receiptPath, std::ios::trunc);
        if (rec) {
            rec << "START=" << (started ? "PASS" : "FAIL") << "\n"
                << "TRANSPORT=" << transportName << "\n"
                << "CONPTY=" << (conpty ? "PASS" : "FAIL") << "\n"
                << "ALIVE_ECHO=" << (alive ? "PASS" : "FAIL") << "\n"
                << "PID=" << livePid << "\n"
                << "EXIT_CODE=" << exitCode << "\n"
                << "OUT_LEN=" << captured.size() << "\n";
            rec.flush();
        }
        startupTrace("runTermSmoke receipt written");

        const bool pass = started && conpty && alive;
        startupTrace(pass ? "term-smoke PASS" : "term-smoke FAIL");

        // --term-quit must not run term.stop() or ~Win32TerminalManager:
        // ClosePseudoConsole/join hung or aborted (EXIT!=0 / FORCE_KILL).
        if (lpCmdLine && std::strstr(lpCmdLine, "--term-quit")) {
            if (livePid != 0) {
                HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, livePid);
                if (hp) {
                    TerminateProcess(hp, 0);
                    CloseHandle(hp);
                }
            }
            startupTrace("term-quit ExitProcess from smoke");
            ::ExitProcess(pass ? 0u : 2u);
        }

        if (started) {
            startupTrace("runTermSmoke before stop");
#if defined(_MSC_VER)
            const int stopRc = stopTerminalSeh(&term);
            if (stopRc < 0) startupTrace("runTermSmoke stop SEH");
            else startupTrace("runTermSmoke after stop");
#else
            try {
                term.stop();
                startupTrace("runTermSmoke after stop");
            } catch (...) {
                startupTrace("runTermSmoke stop exception");
            }
#endif
        }
        return pass ? 0 : 2;
    } catch (const std::exception& ex) {
        startupTrace(ex.what());
        startupTrace("runTermSmoke exception");
        return 3;
    } catch (...) {
        startupTrace("runTermSmoke unknown exception");
        return 3;
    }
}
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    startupTrace("WinMain entered");
    startupTrace(lpCmdLine && *lpCmdLine ? lpCmdLine : "WinMain command line empty");

    // Terminal product ConPTY smoke: run before IDE ctor (no UI/GPU races).
    // --term-quit ExitProcess happens inside runTermSmoke after receipt.
    if (lpCmdLine && std::strstr(lpCmdLine, "--term-smoke")) {
        const int termRc = runTermSmoke(lpCmdLine);
        if (lpCmdLine && std::strstr(lpCmdLine, "--term-quit")) {
            // Fallback if smoke returned instead of ExitProcess.
            startupTrace("term-quit ExitProcess fallback");
            ::ExitProcess(termRc == 0 ? 0 : static_cast<UINT>(termRc));
        }
    }

    // Initialize logger early
    try {
        IDELogger::getInstance().initialize("C:\\RawrXD_IDE.log");
        IDELogger::getInstance().setLevel(IDELogger::Level::DEBUG);
        LOG_INFO("WinMain started - RawrXD Win32 IDE initializing");
    } catch (...) {
        // Fallback to file diagnostic if logger fails
        std::ofstream errLog("C:\\LOGGER_INIT_FAILED.txt");
        errLog << "Logger initialization threw exception" << std::endl;
        errLog.close();
    }

    LOG_DEBUG("Creating Win32IDE instance");
    startupTrace("before Win32IDE constructor");
    Win32IDE ide(hInstance);
    startupTrace("after Win32IDE constructor");
    LOG_DEBUG("Win32IDE constructor completed");

    if (!ide.createWindow()) {
        startupTrace("createWindow failed");
        LOG_ERROR("createWindow() failed");
        MessageBoxA(nullptr, "Failed to create window", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    std::string initialPath;
    // The verification and normal shell launch paths may provide an initial
    // document.  WinMain receives the command line without argv[0]; accept a
    // single quoted or unquoted path and load it only after the editor HWND
    // exists so the normal document/session machinery is used.
    if (lpCmdLine && *lpCmdLine) {
        initialPath = lpCmdLine;
        while (!initialPath.empty() &&
               (initialPath.front() == ' ' || initialPath.front() == '\t')) {
            initialPath.erase(initialPath.begin());
        }
        while (!initialPath.empty() &&
               (initialPath.back() == ' ' || initialPath.back() == '\t')) {
            initialPath.pop_back();
        }
        if (initialPath.size() >= 2 && initialPath.front() == '"' &&
            initialPath.back() == '"') {
            initialPath = initialPath.substr(1, initialPath.size() - 2);
        }
    }
    // Problems GUI gate: RAWRXD_PROBLEMS_FIXTURE binds editor when argv open
    // is missing/unsupported by the harness.
    if (initialPath.empty()) {
        char fixtureEnv[1024];
        fixtureEnv[0] = '\0';
        const DWORD n = GetEnvironmentVariableA(
            "RAWRXD_PROBLEMS_FIXTURE", fixtureEnv, sizeof(fixtureEnv));
        if (n > 0 && n < sizeof(fixtureEnv)) {
            initialPath.assign(fixtureEnv, n);
        }
    }

    LOG_INFO("Main window created successfully");
    startupTrace("createWindow succeeded");
    ide.showWindow();
    startupTrace("showWindow returned");

    bool extQuit = false;
#if defined(RAWRXD_NATIVE_IDE_EXT) && RAWRXD_NATIVE_IDE_EXT
    ExtHostWireResult extWire{};
    const bool extCmd = RawrXD_ExtHost_HandleCmdLine(lpCmdLine, &extWire);
    if (extCmd) {
        startupTrace(extWire.loadOk ? "ext-host wire load OK" : "ext-host wire load FAIL/SKIP");
        initialPath.clear();
        // --ext-quit must DestroyWindow: PostQuitMessage alone leaves HWND alive
        // and ~Win32IDE can block forever joining model-discovery (FORCE_KILL).
        if (lpCmdLine && std::strstr(lpCmdLine, "--ext-quit")) {
            extQuit = true;
            HWND hw = ide.getMainWindow();
            if (hw && IsWindow(hw)) {
                startupTrace("ext-quit DestroyWindow");
                DestroyWindow(hw);
            }
            // Re-arm: nested pumps during onDestroy can consume prior WM_QUIT.
            PostQuitMessage(0);
            startupTrace("ext-quit PostQuitMessage re-armed");
        }
    }
#endif
    if (!initialPath.empty() &&
        !(lpCmdLine && (std::strstr(lpCmdLine, "--ext-") ||
                        std::strstr(lpCmdLine, "--vsix") ||
                        std::strstr(lpCmdLine, "--term-smoke")))) {
        LOG_INFO("Opening initial document: " + initialPath);
        const bool opened = ide.openDocumentPath(initialPath);
        startupTrace(opened ? "initial document opened" : "initial document open FAILED");
        if (!opened) {
            LOG_ERROR("Failed to open initial document: " + initialPath);
        }
    }
    LOG_INFO("Entering message loop");
    startupTrace("entering message loop");
    int rc = ide.runMessageLoop();
    LOG_INFO("Message loop exited with code " + std::to_string(rc));
    if (extQuit) {
        // Skip ~Win32IDE join of discovery/HTTP workers past smoke WaitForExit.
        startupTrace("ext-quit ExitProcess");
        ::ExitProcess(rc == 0 ? 0 : static_cast<UINT>(rc));
    }
    return rc;
}
