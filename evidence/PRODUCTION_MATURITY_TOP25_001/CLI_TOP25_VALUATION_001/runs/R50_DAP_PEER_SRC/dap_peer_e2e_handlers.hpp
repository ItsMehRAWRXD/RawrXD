// dap_peer_e2e_handlers.hpp — BP arm + exception path helpers. PROMOTE=0.
#pragma once
#include "dap_peer_session.hpp"

namespace dap_peer {

inline void OnCreate(PROCESS_INFORMATION& pi, DEBUG_EVENT& ev, uint64_t& bpVa,
                     BYTE& orig, bool& armed) {
    const uint64_t base =
        reinterpret_cast<uint64_t>(ev.u.CreateProcessInfo.lpBaseOfImage);
    ResolveExportVa(pi.hProcess, base, "break_site", &bpVa);
    if (bpVa && ReadRemote(pi.hProcess, bpVa, &orig, 1)) {
        const BYTE cc = 0xCC;
        if (WriteRemote(pi.hProcess, bpVa, &cc, 1)) armed = true;
    }
    if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
}

inline bool OnBp(PROCESS_INFORMATION& pi, DEBUG_EVENT& ev, uint64_t bpVa,
                 BYTE orig, E2EResult& r, bool& wantStep) {
    WriteRemote(pi.hProcess, bpVa, &orig, 1);
    HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, ev.dwThreadId);
    if (th) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(th, &ctx)) {
            ctx.Rip = bpVa;
            SetThreadContext(th, &ctx);
            r.bp_rip = bpVa;
        }
        CloseHandle(th);
    }
    r.bp_hit = 1;
    SetTrapFlag(ev.dwThreadId, true);
    wantStep = true;
    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    return true;
}

// Returns true if caller should continue (skip outer ContinueDebugEvent).
inline bool HandleException(PROCESS_INFORMATION& pi, DEBUG_EVENT& ev,
                            uint64_t bpVa, BYTE orig, bool armed,
                            bool& wantStep, E2EResult& r, DWORD& cont) {
    const auto& er = ev.u.Exception.ExceptionRecord;
    const uint64_t addr = reinterpret_cast<uint64_t>(er.ExceptionAddress);
    if (er.ExceptionCode == EXCEPTION_BREAKPOINT && armed && bpVa &&
        (addr == bpVa || addr == bpVa + 1) && !r.bp_hit) {
        return OnBp(pi, ev, bpVa, orig, r, wantStep);
    }
    if (er.ExceptionCode == EXCEPTION_SINGLE_STEP && wantStep && !r.step_hit) {
        r.step_hit = 1;
        r.step_rip = addr;
        SetTrapFlag(ev.dwThreadId, false);
        wantStep = false;
        r.continued = 1;
        return false;
    }
    if (er.ExceptionCode != EXCEPTION_BREAKPOINT &&
        er.ExceptionCode != EXCEPTION_SINGLE_STEP)
        cont = DBG_EXCEPTION_NOT_HANDLED;
    return false;
}

}  // namespace dap_peer
