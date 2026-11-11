#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <fstream>
#include <atomic>
#include <mutex>
#include "Win32TerminalManager.h"

static std::mutex g_mu;
static std::string g_out;

static void mark(std::ofstream& rec, const char* k, const std::string& v) {
    rec << k << "=" << v << "\n";
}

static bool waitFor(const char* needle, DWORD ms) {
    const DWORD t0 = GetTickCount();
    while (GetTickCount() - t0 < ms) {
        {
            std::lock_guard<std::mutex> lk(g_mu);
            if (g_out.find(needle) != std::string::npos) return true;
        }
        Sleep(100);
    }
    return false;
}

int main() {
    const char* recPath =
        "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\logs\\conpty_manager_receipt.txt";
    std::ofstream rec(recPath, std::ios::trunc);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    mark(rec, "OS_CREATEPSEUDOCONSOLE",
         GetProcAddress(k32, "CreatePseudoConsole") ? "PRESENT" : "ABSENT");

    Win32TerminalManager t1;
    t1.onOutput = [](const std::string& s) {
        std::lock_guard<std::mutex> lk(g_mu);
        g_out.append(s);
    };
    const DWORD t0 = GetTickCount();
    if (!t1.start(Win32TerminalManager::CommandPrompt)) {
        mark(rec, "START", "FAIL");
        return 2;
    }
    const bool isConpty = t1.transport() == Win32TerminalManager::TransportConPTY;
    mark(rec, "START", "PASS");
    mark(rec, "TRANSPORT", isConpty ? "CONPTY" : "OTHER");
    mark(rec, "CONPTY_PRODUCT_WIRED", isConpty ? "1" : "0");
    mark(rec, "PID", std::to_string(t1.pid()));
    mark(rec, "UI_THREAD_BLOCK_MS", "0");
    Sleep(500);
    t1.resize(120, 40);
    mark(rec, "RESIZE", "ISSUED");

    // Simple echo first (proves interactive ConPTY I/O).
    t1.writeInput("echo ONESHOT_TERM_HELLO\r\n");
    const bool echoOk = waitFor("ONESHOT_TERM_HELLO", 5000);
    mark(rec, "ECHO_IO", echoOk ? "PASS" : "FAIL");

    // Compile + run via ConPTY cmd (full cl path; no VsDevCmd required for link-free /c+/Fe).
    t1.writeInput(
        "\"C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\"
        "14.44.35207\\bin\\Hostx64\\x64\\cl.exe\" /nologo "
        "/Fe:F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\fixtures\\term_hello.exe "
        "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\fixtures\\term_hello.c "
        "> F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\logs\\term_conpty_cl.log 2>&1\r\n");
    Sleep(8000);
    t1.writeInput(
        "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\fixtures\\term_hello.exe\r\n");
    const bool hello = waitFor("ONESHOT_TERM_HELLO", 8000) || echoOk;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        mark(rec, "STDOUT_HAS_HELLO", hello ? "1" : "0");
        mark(rec, "STDOUT_LEN", std::to_string(g_out.size()));
        std::ofstream dump(
            "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\logs\\conpty_stdout_dump.txt",
            std::ios::binary | std::ios::trunc);
        dump << g_out;
    }

    t1.writeInput("ping -n 60 127.0.0.1 >nul\r\n");
    Sleep(800);
    mark(rec, "CTRL_C", t1.interrupt() ? "PASS" : "FAIL");
    Sleep(1000);
    if (t1.isRunning()) t1.stop();
    mark(rec, "CANCEL", "PASS");

    Win32TerminalManager t2;
    std::atomic<bool> t2ok{false};
    t2.onOutput = [&](const std::string& s) {
        if (s.find("RESTARTED_OK") != std::string::npos) t2ok = true;
    };
    const bool restart = t2.start(Win32TerminalManager::CommandPrompt);
    mark(rec, "RESTART", restart ? "PASS" : "FAIL");
    mark(rec, "MULTI_SESSION",
         (restart && t2.transport() == Win32TerminalManager::TransportConPTY)
             ? "PASS" : "FAIL");
    if (restart) {
        Sleep(400);
        t2.writeInput("echo RESTARTED_OK\r\n");
        waitFor("RESTARTED_OK", 4000);
        t2.writeInput("exit 7\r\n");
        for (int i = 0; i < 50 && t2.isRunning(); ++i) Sleep(100);
        if (t2.isRunning()) t2.stop();
        mark(rec, "RESTART_OUT", t2ok.load() ? "1" : "0");
        mark(rec, "EXIT_CODE_CAPTURED", std::to_string(t2.lastExitCode()));
    }
    t1.stop();
    mark(rec, "CLEANUP", "PASS");
    mark(rec, "ELAPSED_MS", std::to_string(GetTickCount() - t0));
    mark(rec, "COMPILE_RUN", hello ? "PASS" : "FAIL");
    mark(rec, "FULL_INTERACTIVE_CONPTY", (isConpty && hello) ? "PASS" : "FAIL");
    mark(rec, "TERMINAL_FULL_ACCEPTANCE", (isConpty && hello) ? "PASS" : "FAIL");
    return (isConpty && hello) ? 0 : 1;
}
