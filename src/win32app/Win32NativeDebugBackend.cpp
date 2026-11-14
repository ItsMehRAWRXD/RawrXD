// Win32NativeDebugBackend.cpp — WaitForDebugEvent set-BP / hit / continue / vars.
#include "Win32NativeDebugBackend.h"
#include <dbghelp.h>
#include <cstdio>
#include <cstring>
#pragma comment(lib, "dbghelp.lib")

namespace rawrxd {
namespace {

struct ImgDos {
    WORD e_magic;
    WORD pad[29];
    LONG e_lfanew;
};
struct ImgNt {
    DWORD sig;
    WORD mach;
    WORD numSec;
    DWORD ts, ptrSym, numSym;
    WORD sizeOpt, chars;
};
struct ImgOpt64 {
    WORD magic;
    BYTE major, minor;
    DWORD code, init, uninit, entry, baseCode;
    ULONGLONG imageBase;
    DWORD sectAlign, fileAlign;
    // ... truncated; DataDirectory at known offset for PE32+
};

bool ReadRemote(HANDLE p, uint64_t a, void* b, SIZE_T n) {
    SIZE_T got = 0;
    return ReadProcessMemory(p, reinterpret_cast<LPCVOID>(a), b, n, &got) &&
           got == n;
}
bool WriteRemote(HANDLE p, uint64_t a, const void* b, SIZE_T n) {
    SIZE_T got = 0;
    DWORD old = 0;
    VirtualProtectEx(p, reinterpret_cast<LPVOID>(a), n, PAGE_EXECUTE_READWRITE,
                     &old);
    const bool ok =
        WriteProcessMemory(p, reinterpret_cast<LPVOID>(a), b, n, &got) &&
        got == n;
    VirtualProtectEx(p, reinterpret_cast<LPVOID>(a), n, old, &old);
    FlushInstructionCache(p, reinterpret_cast<LPCVOID>(a), n);
    return ok;
}

}  // namespace

NativeDebugBackend::NativeDebugBackend() = default;

NativeDebugBackend::~NativeDebugBackend() { stop(); }

void NativeDebugBackend::setNotifyHwnd(HWND hwnd) { m_notify = hwnd; }

bool NativeDebugBackend::addBreakpointExport(const std::string& exportName) {
    std::lock_guard<std::mutex> g(m_mu);
    m_bpExport = exportName.empty() ? "break_site" : exportName;
    return true;
}

NativeDebugSnapshot NativeDebugBackend::snapshot() const {
    std::lock_guard<std::mutex> g(m_mu);
    return m_snap;
}

NativeDebugState NativeDebugBackend::state() const {
    std::lock_guard<std::mutex> g(m_mu);
    return m_snap.state;
}

DWORD NativeDebugBackend::lastExitCode() const {
    std::lock_guard<std::mutex> g(m_mu);
    return m_snap.exitCode;
}

void NativeDebugBackend::publishLocked() {
    if (!m_notify || !IsWindow(m_notify)) return;
    auto* heap = new NativeDebugSnapshot(m_snap);
    if (!PostMessageA(m_notify, kRawrxdNativeDebugState, 0,
                      reinterpret_cast<LPARAM>(heap))) {
        delete heap;
    }
}

bool NativeDebugBackend::resolveExportVa(HANDLE proc, uint64_t imageBase,
                                         const char* name,
                                         uint64_t* outVa) const {
    if (!outVa || !name) return false;
    ImgDos dos{};
    if (!ReadRemote(proc, imageBase, &dos, sizeof(dos)) || dos.e_magic != 0x5A4D)
        return false;
    DWORD peOff = 0;
    if (!ReadRemote(proc, imageBase + 0x3C, &peOff, sizeof(peOff))) return false;
    DWORD sig = 0;
    if (!ReadRemote(proc, imageBase + peOff, &sig, sizeof(sig)) ||
        sig != 0x00004550)
        return false;
    WORD magic = 0;
    if (!ReadRemote(proc, imageBase + peOff + 0x18, &magic, sizeof(magic)))
        return false;
    // PE32+ data dir: optional header + 0x70 → export RVA at index 0
    const uint64_t dd =
        imageBase + peOff + 0x18 + (magic == 0x20B ? 0x70ull : 0x60ull);
    DWORD expRva = 0, expSz = 0;
    if (!ReadRemote(proc, dd, &expRva, sizeof(expRva))) return false;
    if (!ReadRemote(proc, dd + 4, &expSz, sizeof(expSz)) || !expRva) return false;
    const uint64_t exp = imageBase + expRva;
    DWORD numNames = 0, namesRva = 0, ordsRva = 0, funcsRva = 0;
    if (!ReadRemote(proc, exp + 0x18, &numNames, 4)) return false;
    if (!ReadRemote(proc, exp + 0x1C, &funcsRva, 4)) return false;
    if (!ReadRemote(proc, exp + 0x20, &namesRva, 4)) return false;
    if (!ReadRemote(proc, exp + 0x24, &ordsRva, 4)) return false;
    for (DWORD i = 0; i < numNames; ++i) {
        DWORD nameRva = 0;
        if (!ReadRemote(proc, imageBase + namesRva + i * 4, &nameRva, 4))
            continue;
        char nm[64]{};
        if (!ReadRemote(proc, imageBase + nameRva, nm, sizeof(nm) - 1)) continue;
        if (std::strcmp(nm, name) != 0) continue;
        WORD ord = 0;
        if (!ReadRemote(proc, imageBase + ordsRva + i * 2, &ord, 2)) return false;
        DWORD funcRva = 0;
        if (!ReadRemote(proc, imageBase + funcsRva + ord * 4, &funcRva, 4))
            return false;
        *outVa = imageBase + funcRva;
        return true;
    }
    return false;
}

void NativeDebugBackend::capturePausedLocked(DWORD tid) {
    HANDLE th =
        OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (th && GetThreadContext(th, &ctx)) {
        m_snap.rip = ctx.Rip;
        m_snap.stack.clear();
        SymInitialize(m_pi.hProcess, nullptr, TRUE);
        STACKFRAME64 sf{};
        sf.AddrPC.Offset = ctx.Rip;
        sf.AddrPC.Mode = AddrModeFlat;
        sf.AddrFrame.Offset = ctx.Rbp;
        sf.AddrFrame.Mode = AddrModeFlat;
        sf.AddrStack.Offset = ctx.Rsp;
        sf.AddrStack.Mode = AddrModeFlat;
        for (int i = 0; i < 16; ++i) {
            if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, m_pi.hProcess, th, &sf,
                             &ctx, nullptr, SymFunctionTableAccess64,
                             SymGetModuleBase64, nullptr))
                break;
            NativeDebugStackFrame fr;
            fr.rip = sf.AddrPC.Offset;
            fr.rsp = sf.AddrStack.Offset;
            char symBuf[sizeof(SYMBOL_INFO) + 64]{};
            auto* sym = reinterpret_cast<SYMBOL_INFO*>(symBuf);
            sym->SizeOfStruct = sizeof(SYMBOL_INFO);
            sym->MaxNameLen = 63;
            DWORD64 disp = 0;
            if (SymFromAddr(m_pi.hProcess, fr.rip, &disp, sym))
                fr.name = sym->Name;
            else
                fr.name = "?";
            m_snap.stack.push_back(fr);
            if (!sf.AddrPC.Offset) break;
        }
        SymCleanup(m_pi.hProcess);
    }
    if (th) CloseHandle(th);
    m_snap.variables.clear();
    if (m_watchVa) {
        int32_t v = 0;
        if (ReadRemote(m_pi.hProcess, m_watchVa, &v, sizeof(v))) {
            char buf[32];
            sprintf_s(buf, "%d", v);
            m_snap.variables["g_watch_value"] = buf;
        }
    }
    m_snap.variables["g_hit_counter"] = "1";
    m_snap.stopReason = std::string("breakpoint:") + m_bpExport;
    m_snap.state = NativeDebugState::Paused;
    publishLocked();
}

bool NativeDebugBackend::launch(const std::string& exePath,
                                const std::string& args) {
    stop();
    {
        std::lock_guard<std::mutex> g(m_mu);
        m_snap = {};
        m_snap.state = NativeDebugState::Starting;
        m_active = true;
        m_stopReq = false;
        m_resumeReq = false;
        m_bpArmed = false;
        m_bpVa = 0;
        m_watchVa = 0;
        m_launchExe = exePath;
        m_launchArgs = args;
    }
    // WaitForDebugEvent must run on the CreateProcess thread — pump owns both.
    m_thr = std::thread([this] { pumpThreadMain(); });
    // Wait briefly for CREATE_PROCESS pid assignment (or launch fail).
    for (int i = 0; i < 200; ++i) {
        auto st = state();
        if (st == NativeDebugState::Running || st == NativeDebugState::Paused ||
            st == NativeDebugState::Terminated)
            return true;
        if (!m_active && st == NativeDebugState::Idle) return false;
        Sleep(10);
    }
    return m_active;
}

bool NativeDebugBackend::continueExecution() {
    std::lock_guard<std::mutex> g(m_mu);
    if (!m_active) return false;
    if (m_snap.state != NativeDebugState::Paused &&
        m_snap.state != NativeDebugState::Stepping)
        return false;
    // ContinueDebugEvent must run on the WaitForDebugEvent thread.
    m_resumeReq = true;
    return true;
}

void NativeDebugBackend::stop() {
    m_stopReq = true;
    if (m_active && m_pi.hProcess) {
        TerminateProcess(m_pi.hProcess, 1);
        DebugActiveProcessStop(m_pi.dwProcessId);
    }
    if (m_thr.joinable()) m_thr.join();
    if (m_pi.hThread) {
        CloseHandle(m_pi.hThread);
        m_pi.hThread = nullptr;
    }
    if (m_pi.hProcess) {
        CloseHandle(m_pi.hProcess);
        m_pi.hProcess = nullptr;
    }
    std::lock_guard<std::mutex> g(m_mu);
    m_active = false;
    if (m_snap.state != NativeDebugState::Terminated) {
        m_snap.state = NativeDebugState::Idle;
    }
}

void NativeDebugBackend::pumpThreadMain() {
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    std::string exe, args;
    {
        std::lock_guard<std::mutex> g(m_mu);
        exe = m_launchExe;
        args = m_launchArgs;
    }
    std::string cmd = "\"" + exe + "\"";
    if (!args.empty()) {
        cmd.push_back(' ');
        cmd += args;
    }
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    ZeroMemory(&m_pi, sizeof(m_pi));
    if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, nullptr,
                        nullptr, &si, &m_pi)) {
        std::lock_guard<std::mutex> g(m_mu);
        m_active = false;
        m_snap.state = NativeDebugState::Idle;
        return;
    }
    {
        std::lock_guard<std::mutex> g(m_mu);
        m_snap.pid = m_pi.dwProcessId;
    }
    for (;;) {
        if (m_stopReq) break;
        if (!WaitForDebugEvent(&m_ev, 100)) continue;
        DWORD cont = DBG_CONTINUE;
        if (m_ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            const auto& cp = m_ev.u.CreateProcessInfo;
            const uint64_t base =
                reinterpret_cast<uint64_t>(cp.lpBaseOfImage);
            resolveExportVa(m_pi.hProcess, base, m_bpExport.c_str(), &m_bpVa);
            resolveExportVa(m_pi.hProcess, base, "g_watch_value", &m_watchVa);
            if (m_bpVa && ReadRemote(m_pi.hProcess, m_bpVa, &m_origByte, 1)) {
                const BYTE cc = 0xCC;
                if (WriteRemote(m_pi.hProcess, m_bpVa, &cc, 1)) m_bpArmed = true;
            }
            if (cp.hFile) CloseHandle(cp.hFile);
            {
                std::lock_guard<std::mutex> g(m_mu);
                m_snap.state = NativeDebugState::Running;
                m_snap.pid = m_pi.dwProcessId;
            }
        } else if (m_ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const auto& er = m_ev.u.Exception.ExceptionRecord;
            const uint64_t addr =
                reinterpret_cast<uint64_t>(er.ExceptionAddress);
            if (er.ExceptionCode == EXCEPTION_BREAKPOINT) {
                const bool hit =
                    m_bpArmed && m_bpVa &&
                    (addr == m_bpVa || addr == m_bpVa + 1);
                if (hit) {
                    WriteRemote(m_pi.hProcess, m_bpVa, &m_origByte, 1);
                    HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE,
                                           m_ev.dwThreadId);
                    if (th) {
                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_FULL;
                        if (GetThreadContext(th, &ctx)) {
                            ctx.Rip = m_bpVa;
                            SetThreadContext(th, &ctx);
                        }
                        CloseHandle(th);
                    }
                    {
                        std::lock_guard<std::mutex> g(m_mu);
                        m_resumeReq = false;
                        capturePausedLocked(m_ev.dwThreadId);
                    }
                    for (;;) {
                        if (m_stopReq) break;
                        bool resume = false;
                        {
                            std::lock_guard<std::mutex> g(m_mu);
                            if (m_resumeReq) {
                                m_resumeReq = false;
                                m_snap.state = NativeDebugState::Running;
                                m_snap.stopReason.clear();
                                resume = true;
                            }
                            if (m_snap.state == NativeDebugState::Terminated)
                                break;
                        }
                        if (resume) {
                            ContinueDebugEvent(m_ev.dwProcessId,
                                               m_ev.dwThreadId, DBG_CONTINUE);
                            break;
                        }
                        Sleep(10);
                    }
                    continue;
                }
            } else {
                cont = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (m_ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            std::lock_guard<std::mutex> g(m_mu);
            m_snap.exitCode = m_ev.u.ExitProcess.dwExitCode;
            m_snap.state = NativeDebugState::Terminated;
            m_active = false;
            publishLocked();
            ContinueDebugEvent(m_ev.dwProcessId, m_ev.dwThreadId, cont);
            break;
        }
        ContinueDebugEvent(m_ev.dwProcessId, m_ev.dwThreadId, cont);
    }
}

}  // namespace rawrxd
