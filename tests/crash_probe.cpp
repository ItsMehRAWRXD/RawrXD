// ============================================================================
// Deliberate crash probe: a child process that hard-faults so the installed
// CrashHandler must capture it and write a .dmp.
//
// A unit test calling reportFatal() proves nothing about a REAL crash, because
// a real fault bypasses C++ stack unwinding. This process faults for real.
//
// Usage:
//   crash_probe.exe child-access-violation   -> dereference nullptr
//   crash_probe.exe child-stack-of-closures  -> deep recursion (stack overflow)
//   crash_probe.exe child-seh-terminate      -> raise STATUS_NONCONTINUABLE_EXCEPTION
// Exit code 0 means the child CRM wrote a dump; 1 means it did not.
// ============================================================================
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#  define _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#endif

#include "crash_handler.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace RawrXD::Resilience;

#ifdef _WIN32
#  include <windows.h>
#endif

namespace {

// A noinline, volatile-sink write so the optimizer cannot elide the fault or
// turn the recursion into a loop.
__declspec(noinline) void writeToNull(int which)
{
    volatile int* p = nullptr;
    *p = which;   // guaranteed access violation
}

__declspec(noinline) void deepRecurse(int depth)
{
    // MUST NOT be a tail call: /O2 turns tail recursion into a loop, which
    // consumes no stack and never overflows - that would test nothing.
    // Using the recursive call's result here prevents that optimization, and
    // the opaque sink keeps the frames alive.
    volatile char pad[4096] = {};
    pad[0] = static_cast<char>(depth);
    pad[sizeof(pad) - 1] = static_cast<char>(depth >> 1);
    if (pad[0] == '\0' && pad[sizeof(pad) - 1] == '\1') return;   // opaque guard

    deepRecurse(depth + 1);

    // Consume the result so the call above cannot be a tail call.
    if (pad[0] != static_cast<char>(depth)) {
        pad[1] = static_cast<char>(depth + 1);
    }
}

std::string g_modeDir;

/// Per-mode dump directory, so the parent loop can reset between children
/// without destroying another mode's evidence.
std::string& dumpDir()
{
    if (g_modeDir.empty()) {
        g_modeDir = (fs::temp_directory_path() / "rawrxd_crash_probe").generic_string();
        const char* env = std::getenv("RAWRXD_PROBE_DIR");
        if (env && *env) g_modeDir = env;
    }
    return g_modeDir;
}

void reportFile(const std::string& what)
{
    // The child records its own outcome so the parent can assert on it.
    const std::string path = dumpDir() + "/probe-result.txt";
    std::ofstream f(fs::u8path(path), std::ios::trunc);
    f << what << "\n";
}

int countDumps()
{
    int dmp = 0;
    int json = 0;
    for (const auto& e : fs::directory_iterator(fs::u8path(dumpDir()))) {
        if (e.path().extension() == ".dmp") ++dmp;
        else if (e.path().extension() == ".json") ++json;
    }
    std::printf("PROBE:   artifacts: .dmp=%d .json=%d\n", dmp, json);
    return dmp;
}

} // anonymous namespace

int main(int argc, char** argv)
{
    const std::string mode = argc > 1 ? argv[1] : "";

    // A clean directory so counts are unambiguous.
    std::error_code ec;
    fs::remove_all(fs::u8path(dumpDir()), ec);
    fs::create_directories(fs::u8path(dumpDir()), ec);

    CrashHandler& h = CrashHandler::instance();
    if (!h.install(dumpDir())) {
        std::printf("PROBE: install failed\n");
        return 2;
    }

    if (mode == "child-access-violation") {
        std::printf("PROBE: dereferencing nullptr\n");
        std::fflush(stdout);
        writeToNull(42);
        // If execution continues here, the SEH filter swallowed the fault.
        reportFile("SURVIVED-ACCESS-VIOLATION");
        return 3;
    }

    if (mode == "child-stack-overflow") {
        std::printf("PROBE: exhausting the stack\n");
        std::fflush(stdout);
        deepRecurse(0);
        reportFile("SURVIVED-STACK-OVERFLOW");
        return 3;
    }

    if (mode == "child-seh-terminate") {
        std::printf("PROBE: raising non-continuable exception\n");
        std::fflush(stdout);
        ::RaiseException(0xE0000001u, EXCEPTION_NONCONTINUABLE_EXCEPTION, 0, nullptr);
        reportFile("SURVIVED-NONCONTINUABLE");
        return 3;
    }

    if (mode == "parent") {
        // Run each child mode with its own cmdline through this same binary,
        // so the child does the crashing (this process must survive to check).
        std::vector<std::string> modes = {
            "child-access-violation", "child-stack-overflow", "child-seh-terminate"};

        int failures = 0;
        for (const auto& m : modes) {
            // Each child starts from a clean dir so the .dmp count is exact.
            const std::string modeDir = dumpDir() + "/" + m;
            ::_putenv_s("RAWRXD_PROBE_DIR", modeDir.c_str());
            std::error_code ec2;
            fs::remove_all(fs::u8path(modeDir), ec2);
            fs::create_directories(fs::u8path(modeDir), ec2);

            STARTUPINFOA si = {};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi = {};
            std::string cmd = "crash_probe.exe " + m;
            std::vector<char> cmdBuf(cmd.begin(), cmd.end());
            cmdBuf.push_back('\0');

            const BOOL ok = ::CreateProcessA(
                nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                &si, &pi);
            if (!ok) {
                std::printf("PROBE: CreateProcess failed (%lu) for %s\n",
                            ::GetLastError(), m.c_str());
                ++failures;
                continue;
            }
            ::WaitForSingleObject(pi.hProcess, 60000);
            DWORD exitCode = 0;
            ::GetExitCodeProcess(pi.hProcess, &exitCode);
            ::CloseHandle(pi.hProcess);
            ::CloseHandle(pi.hThread);

            const std::string savedDir = dumpDir();
            dumpDir() = modeDir;
            const int dumps = countDumps();
            g_modeDir = savedDir;
            std::printf("PROBE: %-26s child_exit=0x%08lx dumps=%d\n",
                        m.c_str(), exitCode, dumps);
            if (dumps < 1) {
                std::printf("PROBE: NO CRASH ARTIFACT WRITTEN for %s\n", m.c_str());
                ++failures;
            }
        }
        return failures == 0 ? 0 : 1;
    }

    std::printf("usage: crash_probe.exe [child-access-violation|child-stack-overflow|"
                "child-seh-terminate|parent]\n");
    return 2;
}
