#pragma once
// Agent owns the debugger — not stdout stack scraping.
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace rawr::product {

struct DebugFrame {
    uint64_t pc = 0;
    uint64_t sp = 0;
    char mod[64]{};
};

struct DebugSnap {
    uint32_t exceptionCode = 0;
    uint64_t exceptionAddr = 0;
    uint64_t rip = 0, rsp = 0, rbp = 0;
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
    int threadCount = 0;
    int frameCount = 0;
    DebugFrame frames[32]{};
    int fromDebugger = 0; // 1 = live debug events, never stdout
};

struct AgentDebugSession {
#ifdef _WIN32
    PROCESS_INFORMATION pi{};
    bool active = false;
    bool stopped = false;
    DEBUG_EVENT ev{};
#endif

    bool launch(const char* exe, const char* args = "",
                const char* cwd = nullptr) {
#ifdef _WIN32
        if (active) terminate();
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        std::string cmd = std::string("\"") + exe + "\"";
        if (args && args[0]) {
            cmd.push_back(' ');
            cmd += args;
        }
        std::vector<char> buf(cmd.begin(), cmd.end());
        buf.push_back(0);
        ZeroMemory(&pi, sizeof(pi));
        DWORD flags = DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE;
        if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
                            flags, nullptr, cwd, &si, &pi))
            return false;
        active = true;
        stopped = false;
        return true;
#else
        (void)exe;
        (void)args;
        (void)cwd;
        return false;
#endif
    }

    // Pump until exception/breakpoint or timeout. Owns the stop reason.
    bool waitStop(uint32_t timeoutMs, DebugSnap& out) {
#ifdef _WIN32
        if (!active) return false;
        out = {};
        out.fromDebugger = 1;
        const DWORD t0 = GetTickCount();
        for (;;) {
            if (GetTickCount() - t0 > timeoutMs) return false;
            if (!WaitForDebugEvent(&ev, 200)) continue;
            DWORD cont = DBG_CONTINUE;
            if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                const auto& ex = ev.u.Exception.ExceptionRecord;
                const DWORD code = ex.ExceptionCode;
                if (code == EXCEPTION_BREAKPOINT &&
                    ev.u.Exception.dwFirstChance) {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
                    continue; // loader BP
                }
                out.exceptionCode = code;
                out.exceptionAddr = (uint64_t)(uintptr_t)ex.ExceptionAddress;
                capture(ev.dwThreadId, out);
                stopped = true;
                return true;
            }
            if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
                active = false;
                return false;
            }
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
        }
#else
        (void)timeoutMs;
        (void)out;
        return false;
#endif
    }

    bool resume() {
#ifdef _WIN32
        if (!active || !stopped) return false;
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        stopped = false;
        return true;
#else
        return false;
#endif
    }

    void terminate() {
#ifdef _WIN32
        if (!active) return;
        TerminateProcess(pi.hProcess, 1);
        DebugActiveProcessStop(pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        active = false;
        stopped = false;
#endif
    }

#ifdef _WIN32
    void capture(DWORD tid, DebugSnap& out) {
        HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                               FALSE, tid);
        if (!th) return;
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(th, &ctx)) {
            out.rip = ctx.Rip;
            out.rsp = ctx.Rsp;
            out.rbp = ctx.Rbp;
            out.rax = ctx.Rax;
            out.rbx = ctx.Rbx;
            out.rcx = ctx.Rcx;
            out.rdx = ctx.Rdx;
        }
        out.threadCount = 1;
        SymInitialize(pi.hProcess, nullptr, TRUE);
        STACKFRAME64 sf{};
        sf.AddrPC.Offset = ctx.Rip;
        sf.AddrPC.Mode = AddrModeFlat;
        sf.AddrFrame.Offset = ctx.Rbp;
        sf.AddrFrame.Mode = AddrModeFlat;
        sf.AddrStack.Offset = ctx.Rsp;
        sf.AddrStack.Mode = AddrModeFlat;
        out.frameCount = 0;
        while (out.frameCount < 32 &&
               StackWalk64(IMAGE_FILE_MACHINE_AMD64, pi.hProcess, th, &sf,
                           &ctx, nullptr, SymFunctionTableAccess64,
                           SymGetModuleBase64, nullptr)) {
            auto& f = out.frames[out.frameCount++];
            f.pc = sf.AddrPC.Offset;
            f.sp = sf.AddrStack.Offset;
            DWORD64 base = SymGetModuleBase64(pi.hProcess, f.pc);
            if (base) {
                char name[MAX_PATH]{};
                if (GetModuleFileNameExA(pi.hProcess, (HMODULE)base, name,
                                         MAX_PATH)) {
                    const char* slash = strrchr(name, '\\');
                    strncpy(f.mod, slash ? slash + 1 : name, sizeof(f.mod) - 1);
                }
            }
            if (sf.AddrPC.Offset == 0) break;
        }
        SymCleanup(pi.hProcess);
        CloseHandle(th);
    }
#endif
};

inline std::string ReasonFromSnap(const DebugSnap& s) {
    char buf[256];
    snprintf(buf, sizeof(buf),
             "DBG_OWN exception=0x%08X addr=0x%llX rip=0x%llX frames=%d "
             "fromDebugger=%d",
             s.exceptionCode, (unsigned long long)s.exceptionAddr,
             (unsigned long long)s.rip, s.frameCount, s.fromDebugger);
    return buf;
}

} // namespace rawr::product
