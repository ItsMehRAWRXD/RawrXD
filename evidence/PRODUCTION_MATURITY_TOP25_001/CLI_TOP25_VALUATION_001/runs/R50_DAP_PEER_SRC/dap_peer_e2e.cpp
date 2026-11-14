// dap_peer_e2e.cpp — CreateProcess DEBUG + WFDE + INT3 + TF step. PROMOTE=0.
#include "dap_peer_session.hpp"
#include "dap_peer_e2e_handlers.hpp"
#include <string>
#include <vector>

namespace dap_peer {

bool SetTrapFlag(DWORD tid, bool on) {
    HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!th) return false;
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL;
    bool ok = false;
    if (GetThreadContext(th, &ctx)) {
        if (on)
            ctx.EFlags |= 0x100;
        else
            ctx.EFlags &= ~0x100u;
        ok = SetThreadContext(th, &ctx) != 0;
    }
    CloseHandle(th);
    return ok;
}

E2EResult RunDapCliE2E(const char* debuggee) {
    E2EResult r{};
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::string cmd = std::string("\"") + debuggee + "\"";
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, nullptr,
                        nullptr, &si, &pi))
        return r;
    r.launched = 1;
    uint64_t bpVa = 0;
    BYTE orig = 0x90;
    bool armed = false, wantStep = false;
    const DWORD t0 = GetTickCount();
    DEBUG_EVENT ev{};
    while (GetTickCount() - t0 < 12000) {
        if (!WaitForDebugEvent(&ev, 200)) continue;
        r.wfde = 1;
        DWORD cont = DBG_CONTINUE;
        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            OnCreate(pi, ev, bpVa, orig, armed);
        } else if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            if (HandleException(pi, ev, bpVa, orig, armed, wantStep, r, cont))
                continue;
        } else if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            r.exited = 1;
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
            break;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
    }
    if (!r.exited) {
        TerminateProcess(pi.hProcess, 1);
        DebugActiveProcessStop(pi.dwProcessId);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return r;
}

}  // namespace dap_peer
