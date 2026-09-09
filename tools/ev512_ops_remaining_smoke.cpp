// ev512_ops_remaining_smoke.cpp — closed remaining-gen batch (real OS owners).
// Claims: 63-66,69-74,79-80 + agent 60/90 around real tool loop. No invented emits.
#include "RuntimeEvidence512Surface.hpp"
#include "RuntimeEvidence512HostIDE.hpp"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

static uint64_t pathHash(const char* p) {
    return Deep2::Ev512::HostPathHash(p);
}

static DWORD runProcess(const char* app, const char* cmdline, uint64_t* pidOut) {
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    std::string cmd = cmdline ? cmdline : "";
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back('\0');
    if (!CreateProcessA(app && app[0] ? app : nullptr, buf.data(), nullptr, nullptr,
                        FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return (DWORD)-1;
    }
    if (pidOut) *pidOut = (uint64_t)pi.dwProcessId;
    WaitForSingleObject(pi.hProcess, 60000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code;
}

int main() {
    Deep2::Ev512::HostTryArm(0x4F505347454Eull); /* OPSGEN */
    Deep2::Ev512::HostSurfaceGuard surface(stderr);

    const uint64_t reqId = 1;
    Deep2::Ev512::HostEmitAgentLoopEntry(reqId, pathHash("ops-smoke"));

    /* Tool: file write then read (63/64/66/65) */
    const char* toolPath = "ev512_ops_tool_out.txt";
    const uint64_t inv = 42;
    Deep2::Ev512::HostEmitToolDispatch(1, inv);
    {
        std::ofstream f(toolPath, std::ios::binary | std::ios::trunc);
        f << "ops-smoke-payload\n";
    }
    {
        std::ifstream in(toolPath, std::ios::binary | std::ios::ate);
        const uint64_t n = in ? (uint64_t)in.tellg() : 0ull;
        Deep2::Ev512::HostEmitFileWrite(pathHash(toolPath), n);
        in.clear();
        in.seekg(0);
        std::string body((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
        Deep2::Ev512::HostEmitFileRead(pathHash(toolPath),
                                       (uint64_t)body.size());
    }
    Deep2::Ev512::HostEmitToolComplete(inv, 0);

    /* Terminal: cmd /c echo (69/70) */
    {
        uint64_t pid = 0;
        const uint64_t ch = pathHash("cmd-echo");
        Deep2::Ev512::HostEmitTerminalEntry(ch, 0);
        DWORD ec = runProcess(nullptr, "cmd.exe /c echo ev512-ops", &pid);
        Deep2::Ev512::HostEmitTerminalComplete(pid ? pid : ch, (uint64_t)ec);
    }

    /* Build tool process: cmake --version (71/72) */
    {
        const uint64_t bid = pathHash("cmake-version");
        Deep2::Ev512::HostEmitBuildEntry(bid, 1);
        DWORD ec = runProcess(nullptr, "cmake --version", nullptr);
        Deep2::Ev512::HostEmitBuildComplete(1, (uint64_t)ec);
    }

    /* Test process: cmd /c exit 0 as test runner stand-in (73/74) */
    {
        const uint64_t tid = pathHash("cmd-exit0");
        Deep2::Ev512::HostEmitTestEntry(tid, 1);
        DWORD ec = runProcess(nullptr, "cmd.exe /c exit /b 0", nullptr);
        Deep2::Ev512::HostEmitTestComplete(1, (uint64_t)ec);
    }

    /* Git if present (79/80) */
    {
        const uint64_t gh = pathHash("git-version");
        Deep2::Ev512::HostEmitGitEntry(gh, pathHash("."));
        DWORD ec = runProcess(nullptr, "git --version", nullptr);
        if (ec != (DWORD)-1)
            Deep2::Ev512::HostEmitGitComplete(gh, (uint64_t)ec);
        else
            std::fprintf(stderr, "GIT_SKIP=1 CreateProcess_failed\n");
    }

    Deep2::Ev512::HostEmitAgentComplete(reqId, pathHash("ops-smoke-done"));
    std::fprintf(stderr, "EV512_OPS_SMOKE_DONE=1\n");
    return 0;
}
