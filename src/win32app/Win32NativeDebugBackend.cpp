#include "Win32NativeDebugBackend.h"

#include <dbghelp.h>
#include <psapi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

namespace rawrxd {
namespace {

constexpr DWORD kTrapFlag = 0x100;

bool readProc(HANDLE process, uint64_t addr, void* buf, size_t n) {
    SIZE_T got = 0;
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(addr), buf, n, &got) && got == n;
}

bool writeProc(HANDLE process, uint64_t addr, const void* buf, size_t n) {
    SIZE_T put = 0;
    DWORD oldProtect = 0;
    auto* p = reinterpret_cast<LPVOID>(addr);
    if (!VirtualProtectEx(process, p, n, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    const bool ok = WriteProcessMemory(process, p, buf, n, &put) && put == n;
    DWORD unused = 0;
    VirtualProtectEx(process, p, n, oldProtect, &unused);
    FlushInstructionCache(process, p, n);
    return ok;
}

}  // namespace

Win32NativeDebugBackend::Win32NativeDebugBackend() = default;

Win32NativeDebugBackend::~Win32NativeDebugBackend() {
    stop(true);
}

void Win32NativeDebugBackend::setOutputCallback(OutputFn fn) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_onOutput = std::move(fn);
}

void Win32NativeDebugBackend::setStateCallback(StateFn fn) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_onState = std::move(fn);
}

NativeDebugState Win32NativeDebugBackend::state() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_state;
}

bool Win32NativeDebugBackend::isActive() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_state == NativeDebugState::Running ||
           m_state == NativeDebugState::Paused ||
           m_state == NativeDebugState::Stepping ||
           m_state == NativeDebugState::Launching;
}

bool Win32NativeDebugBackend::launch(const std::string& exePath,
                                     const std::string& args,
                                     const std::string& workingDir) {
    stop(true);

    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_exePath = exePath;
        m_args = args;
        m_cwd = workingDir;
        m_exitCode = 0;
        m_imageBase = 0;
        m_exports.clear();
        m_variables.clear();
        m_threads.clear();
        // Preserve deferred export breakpoints (address==0 + label) set before launch.
        m_bps.erase(std::remove_if(m_bps.begin(), m_bps.end(),
                                   [](const NativeDebugBp& b) {
                                       return b.address != 0 || b.label.empty();
                                   }),
                    m_bps.end());
        for (auto& bp : m_bps) {
            bp.applied = false;
            bp.hitCount = 0;
            bp.original = 0;
        }
        m_stopRequested = false;
        m_expectStep = false;
        m_pendingContinue = false;
        m_breakOnNext = false;
        m_stopReason.clear();
        ZeroMemory(&m_pi, sizeof(m_pi));
        m_state = NativeDebugState::Launching;
        m_running = true;
    }

    // CreateProcess(DEBUG_*) binds debug events to THIS thread. The event
    // loop thread must therefore own CreateProcess — never the UI caller.
    m_thread = std::thread(&Win32NativeDebugBackend::eventThreadMain, this);

    for (int i = 0; i < 500; ++i) {
        NativeDebugState st = state();
        DWORD pid = 0;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            pid = m_pi.dwProcessId;
            if (st == NativeDebugState::Error) {
                return false;
            }
            if (pid != 0 && (st == NativeDebugState::Running ||
                             st == NativeDebugState::Paused ||
                             st == NativeDebugState::Stepping)) {
                if (m_onOutput) {
                    m_onOutput(std::string("[native-debug] launched pid=") +
                               std::to_string(pid));
                }
                return true;
            }
        }
        Sleep(10);
    }
    return isActive() || state() == NativeDebugState::Running;
}

bool Win32NativeDebugBackend::stop(bool terminate) {
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_stopRequested = true;
        if (m_pi.hProcess && terminate && m_state != NativeDebugState::Terminated &&
            m_state != NativeDebugState::Idle) {
            TerminateProcess(m_pi.hProcess, 0xDEAD);
        }
        if (m_state == NativeDebugState::Paused || m_state == NativeDebugState::Stepping) {
            m_pendingContinue = true;
            m_continueStatus = DBG_CONTINUE;
        }
    }

    if (m_thread.joinable()) {
        m_thread.join();
    }

    std::lock_guard<std::mutex> lock(m_mu);
    cleanupHandles();
    m_running = false;
    if (m_state != NativeDebugState::Terminated) {
        m_state = NativeDebugState::Idle;
    }
    return true;
}

bool Win32NativeDebugBackend::restart() {
    std::string exe, args, cwd;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        exe = m_exePath;
        args = m_args;
        cwd = m_cwd;
    }
    if (exe.empty()) {
        return false;
    }
    return launch(exe, args, cwd);
}

bool Win32NativeDebugBackend::continueExecution() {
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_state != NativeDebugState::Paused && m_state != NativeDebugState::Stepping) {
        return false;
    }
    // Re-apply software BPs before resume (except at current RIP temporarily handled in step).
    for (auto& bp : m_bps) {
        if (bp.enabled && bp.address != m_currentRip) {
            applyBreakpoint(bp);
        }
    }
    m_expectStep = false;
    m_pendingContinue = true;
    m_continueStatus = DBG_CONTINUE;
    m_state = NativeDebugState::Running;
    m_stopReason = "continue";
    return true;
}

bool Win32NativeDebugBackend::pauseExecution() {
    std::lock_guard<std::mutex> lock(m_mu);
    if (!m_pi.hProcess || m_state != NativeDebugState::Running) {
        return false;
    }
    return DebugBreakProcess(m_pi.hProcess) != FALSE;
}

bool Win32NativeDebugBackend::stepIntoUnlocked() {
    if (m_state != NativeDebugState::Paused) {
        return false;
    }
    if (auto* bp = findBpByAddress(m_currentRip)) {
        restoreBreakpoint(*bp);
    }
    if (!setTrapFlag(true)) {
        return false;
    }
    m_expectStep = true;
    m_breakOnNext = true;
    m_pendingContinue = true;
    m_continueStatus = DBG_CONTINUE;
    m_state = NativeDebugState::Stepping;
    m_stopReason = "step_into";
    return true;
}

bool Win32NativeDebugBackend::stepInto() {
    std::lock_guard<std::mutex> lock(m_mu);
    return stepIntoUnlocked();
}

bool Win32NativeDebugBackend::stepOver() {
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_state != NativeDebugState::Paused || !m_pi.hProcess) {
        return false;
    }
    uint8_t op = 0;
    if (!readProc(m_pi.hProcess, m_currentRip, &op, 1)) {
        return false;
    }
    if (op == 0xE8) {
        const uint64_t next = m_currentRip + 5;
        NativeDebugBp one{};
        one.address = next;
        one.label = "step_over_return";
        one.enabled = true;
        applyBreakpoint(one);
        m_bps.push_back(one);
        if (auto* bp = findBpByAddress(m_currentRip)) {
            restoreBreakpoint(*bp);
        }
        m_expectStep = false;
        m_pendingContinue = true;
        m_continueStatus = DBG_CONTINUE;
        m_state = NativeDebugState::Stepping;
        m_stopReason = "step_over";
        return true;
    }
    return stepIntoUnlocked();
}

bool Win32NativeDebugBackend::stepOut() {
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_state != NativeDebugState::Paused || !m_pi.hProcess) {
        return false;
    }
    uint64_t ret = 0;
    if (!readProc(m_pi.hProcess, m_currentRsp, &ret, sizeof(ret)) || ret == 0) {
        return false;
    }
    NativeDebugBp one{};
    one.address = ret;
    one.label = "step_out_return";
    one.enabled = true;
    applyBreakpoint(one);
    m_bps.push_back(one);
    if (auto* bp = findBpByAddress(m_currentRip)) {
        restoreBreakpoint(*bp);
    }
    m_expectStep = false;
    m_pendingContinue = true;
    m_continueStatus = DBG_CONTINUE;
    m_state = NativeDebugState::Stepping;
    m_stopReason = "step_out";
    return true;
}

bool Win32NativeDebugBackend::addBreakpointAddressUnlocked(uint64_t address,
                                                           const std::string& label) {
    if (address == 0) {
        NativeDebugBp bp{};
        bp.label = label;
        bp.enabled = true;
        m_bps.push_back(bp);
        return true;
    }
    if (findBpByAddress(address)) {
        return true;
    }
    NativeDebugBp bp{};
    bp.address = address;
    bp.label = label;
    bp.enabled = true;
    if (m_pi.hProcess && (m_state == NativeDebugState::Paused ||
                          m_state == NativeDebugState::Running ||
                          m_state == NativeDebugState::Launching ||
                          m_state == NativeDebugState::Stepping)) {
        if (!applyBreakpoint(bp)) {
            return false;
        }
    }
    m_bps.push_back(bp);
    return true;
}

bool Win32NativeDebugBackend::addBreakpointExport(const std::string& exportName) {
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_exports.find(exportName);
    if (it == m_exports.end()) {
        return addBreakpointAddressUnlocked(0, exportName);
    }
    return addBreakpointAddressUnlocked(it->second, exportName);
}

bool Win32NativeDebugBackend::addBreakpointAddress(uint64_t address, const std::string& label) {
    std::lock_guard<std::mutex> lock(m_mu);
    return addBreakpointAddressUnlocked(address, label);
}

bool Win32NativeDebugBackend::removeBreakpointAddress(uint64_t address) {
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = std::find_if(m_bps.begin(), m_bps.end(),
                           [&](const NativeDebugBp& b) { return b.address == address; });
    if (it == m_bps.end()) {
        return false;
    }
    restoreBreakpoint(*it);
    m_bps.erase(it);
    return true;
}

bool Win32NativeDebugBackend::clearBreakpoints() {
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& bp : m_bps) {
        restoreBreakpoint(bp);
    }
    m_bps.clear();
    return true;
}

bool Win32NativeDebugBackend::readMemory(uint64_t address, void* buffer, size_t size) const {
    std::lock_guard<std::mutex> lock(m_mu);
    if (!m_pi.hProcess || !buffer || size == 0) {
        return false;
    }
    return readProc(m_pi.hProcess, address, buffer, size);
}

bool Win32NativeDebugBackend::evaluateExpression(const std::string& expression,
                                                 std::string& outValue) const {
    std::lock_guard<std::mutex> lock(m_mu);
    auto vit = m_variables.find(expression);
    if (vit != m_variables.end()) {
        outValue = vit->second;
        return true;
    }
    auto eit = m_exports.find(expression);
    if (eit != m_exports.end() && m_pi.hProcess) {
        int32_t v = 0;
        if (readProc(m_pi.hProcess, eit->second, &v, sizeof(v))) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%d (0x%llX)", v,
                          static_cast<unsigned long long>(eit->second));
            outValue = buf;
            return true;
        }
    }
    if (expression.rfind("0x", 0) == 0 || expression.rfind("0X", 0) == 0) {
        uint64_t addr = 0;
        if (sscanf_s(expression.c_str(), "%llx", &addr) == 1 ||
            sscanf_s(expression.c_str(), "0x%llx", &addr) == 1) {
            int32_t v = 0;
            if (m_pi.hProcess && readProc(m_pi.hProcess, addr, &v, sizeof(v))) {
                char buf[32];
                std::snprintf(buf, sizeof(buf), "%d", v);
                outValue = buf;
                return true;
            }
        }
    }
    outValue = "<unevaluable>";
    return false;
}

NativeDebugSnapshot Win32NativeDebugBackend::snapshot() const {
    std::lock_guard<std::mutex> lock(m_mu);
    NativeDebugSnapshot s;
    s.state = m_state;
    s.pid = m_pi.dwProcessId;
    s.exitCode = m_exitCode;
    s.rip = m_currentRip;
    s.rsp = m_currentRsp;
    s.imageBase = m_imageBase;
    s.stopReason = m_stopReason;
    s.threads = m_threads;
    s.exports = m_exports;
    s.variables = m_variables;
    walkStackUnlocked(s.stack);
    return s;
}

void Win32NativeDebugBackend::cleanupHandles() {
    if (m_pi.hThread) {
        CloseHandle(m_pi.hThread);
        m_pi.hThread = nullptr;
    }
    if (m_pi.hProcess) {
        CloseHandle(m_pi.hProcess);
        m_pi.hProcess = nullptr;
    }
    for (auto& t : m_threads) {
        if (t.handle) {
            CloseHandle(t.handle);
            t.handle = nullptr;
        }
    }
    m_activeThread = nullptr;
    m_activeTid = 0;
    ZeroMemory(&m_pi, sizeof(m_pi));
}

NativeDebugBp* Win32NativeDebugBackend::findBpByAddress(uint64_t address) {
    for (auto& bp : m_bps) {
        if (bp.address == address) {
            return &bp;
        }
    }
    return nullptr;
}

bool Win32NativeDebugBackend::applyBreakpoint(NativeDebugBp& bp) {
    if (!m_pi.hProcess || bp.address == 0 || bp.applied) {
        return bp.address != 0;
    }
    if (!readProc(m_pi.hProcess, bp.address, &bp.original, 1)) {
        return false;
    }
    const uint8_t int3 = 0xCC;
    if (!writeProc(m_pi.hProcess, bp.address, &int3, 1)) {
        return false;
    }
    bp.applied = true;
    return true;
}

bool Win32NativeDebugBackend::restoreBreakpoint(NativeDebugBp& bp) {
    if (!m_pi.hProcess || !bp.applied || bp.address == 0) {
        bp.applied = false;
        return true;
    }
    if (!writeProc(m_pi.hProcess, bp.address, &bp.original, 1)) {
        return false;
    }
    bp.applied = false;
    return true;
}

bool Win32NativeDebugBackend::getContext(CONTEXT& ctx) const {
    if (!m_activeThread) {
        return false;
    }
    ctx.ContextFlags = CONTEXT_FULL;
    return GetThreadContext(m_activeThread, &ctx) != FALSE;
}

bool Win32NativeDebugBackend::setContext(const CONTEXT& ctx) const {
    if (!m_activeThread) {
        return false;
    }
    return SetThreadContext(m_activeThread, &ctx) != FALSE;
}

bool Win32NativeDebugBackend::setTrapFlag(bool enable) {
    CONTEXT ctx{};
    if (!getContext(ctx)) {
        return false;
    }
    if (enable) {
        ctx.EFlags |= kTrapFlag;
    } else {
        ctx.EFlags &= ~kTrapFlag;
    }
    return setContext(ctx);
}

std::string Win32NativeDebugBackend::formatException(DWORD code) const {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "exception=0x%08lX", static_cast<unsigned long>(code));
    return buf;
}

bool Win32NativeDebugBackend::resolveExportsFromImage() {
    if (!m_pi.hProcess || m_imageBase == 0) {
        return false;
    }
    IMAGE_DOS_HEADER dos{};
    if (!readProc(m_pi.hProcess, m_imageBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!readProc(m_pi.hProcess, m_imageBase + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return false;
    }
    IMAGE_EXPORT_DIRECTORY exp{};
    if (!readProc(m_pi.hProcess, m_imageBase + dir.VirtualAddress, &exp, sizeof(exp))) {
        return false;
    }
    std::vector<DWORD> names(exp.NumberOfNames);
    std::vector<WORD> ords(exp.NumberOfNames);
    std::vector<DWORD> funcs(exp.NumberOfFunctions);
    if (exp.NumberOfNames == 0 || exp.NumberOfFunctions == 0) {
        return false;
    }
    if (!readProc(m_pi.hProcess, m_imageBase + exp.AddressOfNames, names.data(),
                  names.size() * sizeof(DWORD))) {
        return false;
    }
    if (!readProc(m_pi.hProcess, m_imageBase + exp.AddressOfNameOrdinals, ords.data(),
                  ords.size() * sizeof(WORD))) {
        return false;
    }
    if (!readProc(m_pi.hProcess, m_imageBase + exp.AddressOfFunctions, funcs.data(),
                  funcs.size() * sizeof(DWORD))) {
        return false;
    }
    m_exports.clear();
    for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
        char name[256]{};
        if (!readProc(m_pi.hProcess, m_imageBase + names[i], name, sizeof(name) - 1)) {
            continue;
        }
        name[sizeof(name) - 1] = 0;
        const WORD ord = ords[i];
        if (ord >= funcs.size()) {
            continue;
        }
        uint64_t abs = m_imageBase + funcs[ord];
        // Follow incremental-link thunks: E9 rel32 or FF 25 abs64.
        uint8_t stub[16]{};
        if (readProc(m_pi.hProcess, abs, stub, sizeof(stub))) {
            if (stub[0] == 0xE9) {
                const int32_t rel = *reinterpret_cast<int32_t*>(&stub[1]);
                abs = abs + 5 + static_cast<int64_t>(rel);
            } else if (stub[0] == 0xFF && stub[1] == 0x25) {
                const int32_t disp = *reinterpret_cast<int32_t*>(&stub[2]);
                const uint64_t slot = abs + 6 + static_cast<int64_t>(disp);
                uint64_t target = 0;
                if (readProc(m_pi.hProcess, slot, &target, sizeof(target)) && target) {
                    abs = target;
                }
            }
        }
        m_exports[name] = abs;
    }
    // Bind deferred export breakpoints.
    for (auto& bp : m_bps) {
        if (bp.address == 0 && !bp.label.empty()) {
            auto it = m_exports.find(bp.label);
            if (it != m_exports.end()) {
                bp.address = it->second;
                const bool applied = applyBreakpoint(bp);
                if (m_onOutput) {
                    char detail[160];
                    std::snprintf(detail, sizeof(detail),
                                  "[native-debug] BP_BIND label=%s address=0x%llX applied=%d",
                                  bp.label.c_str(),
                                  static_cast<unsigned long long>(bp.address),
                                  applied ? 1 : 0);
                    m_onOutput(detail);
                }
            } else if (m_onOutput) {
                m_onOutput("[native-debug] BP_BIND_MISSING label=" + bp.label);
            }
        } else if (bp.enabled && bp.address != 0 && !bp.applied) {
            const bool applied = applyBreakpoint(bp);
            if (m_onOutput) {
                char detail[160];
                std::snprintf(detail, sizeof(detail),
                              "[native-debug] BP_REAPPLY label=%s address=0x%llX applied=%d",
                              bp.label.c_str(),
                              static_cast<unsigned long long>(bp.address),
                              applied ? 1 : 0);
                m_onOutput(detail);
            }
        }
    }
    return !m_exports.empty();
}

bool Win32NativeDebugBackend::refreshVariablesUnlocked() {
    m_variables.clear();
    if (!m_pi.hProcess) {
        return false;
    }
    auto loadInt = [&](const char* name) {
        auto it = m_exports.find(name);
        if (it == m_exports.end()) {
            return;
        }
        int32_t v = 0;
        if (readProc(m_pi.hProcess, it->second, &v, sizeof(v))) {
            m_variables[name] = std::to_string(v);
        }
    };
    loadInt("g_watch_value");
    loadInt("g_hit_counter");
    char ripBuf[32];
    std::snprintf(ripBuf, sizeof(ripBuf), "0x%llX",
                  static_cast<unsigned long long>(m_currentRip));
    m_variables["$rip"] = ripBuf;
    char rspBuf[32];
    std::snprintf(rspBuf, sizeof(rspBuf), "0x%llX",
                  static_cast<unsigned long long>(m_currentRsp));
    m_variables["$rsp"] = rspBuf;
    return true;
}

bool Win32NativeDebugBackend::walkStackUnlocked(std::vector<NativeDebugFrame>& out) const {
    out.clear();
    if (!m_pi.hProcess || !m_activeThread) {
        return false;
    }
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(m_activeThread, &ctx)) {
        return false;
    }
    STACKFRAME64 frame{};
    frame.AddrPC.Offset = ctx.Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = ctx.Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = ctx.Rsp;
    frame.AddrStack.Mode = AddrModeFlat;

    SymInitialize(m_pi.hProcess, nullptr, FALSE);
    for (int i = 0; i < 32; ++i) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, m_pi.hProcess, m_activeThread, &frame, &ctx,
                         nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
            break;
        }
        if (frame.AddrPC.Offset == 0) {
            break;
        }
        NativeDebugFrame f;
        f.rip = frame.AddrPC.Offset;
        f.rsp = frame.AddrStack.Offset;
        char modPath[MAX_PATH]{};
        HMODULE mods[64]{};
        DWORD needed = 0;
        if (EnumProcessModules(m_pi.hProcess, mods, sizeof(mods), &needed)) {
            for (DWORD mi = 0; mi < needed / sizeof(HMODULE); ++mi) {
                MODULEINFO info{};
                if (!GetModuleInformation(m_pi.hProcess, mods[mi], &info, sizeof(info))) {
                    continue;
                }
                const uint64_t base = reinterpret_cast<uint64_t>(info.lpBaseOfDll);
                if (f.rip >= base && f.rip < base + info.SizeOfImage) {
                    GetModuleBaseNameA(m_pi.hProcess, mods[mi], modPath, MAX_PATH);
                    f.module = modPath;
                    break;
                }
            }
        }
        for (const auto& e : m_exports) {
            if (e.second == f.rip || (f.rip >= e.second && f.rip < e.second + 0x40)) {
                f.symbol = e.first;
                break;
            }
        }
        if (f.symbol.empty()) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llX",
                          static_cast<unsigned long long>(f.rip));
            f.symbol = buf;
        }
        out.push_back(f);
    }
    SymCleanup(m_pi.hProcess);
    return !out.empty();
}

void Win32NativeDebugBackend::publishState(const std::string& reason) {
    m_stopReason = reason;
    refreshVariablesUnlocked();
    if (!m_onState) {
        return;
    }
    // Callback must not re-enter backend APIs (PostMessage / queue only).
    NativeDebugSnapshot s;
    s.state = m_state;
    s.pid = m_pi.dwProcessId;
    s.exitCode = m_exitCode;
    s.rip = m_currentRip;
    s.rsp = m_currentRsp;
    s.imageBase = m_imageBase;
    s.stopReason = m_stopReason;
    s.threads = m_threads;
    s.exports = m_exports;
    s.variables = m_variables;
    walkStackUnlocked(s.stack);
    m_onState(s);
}

void Win32NativeDebugBackend::eventThreadMain() {
    // Own CreateProcess on the WaitForDebugEvent thread (Windows requirement).
    {
        std::lock_guard<std::mutex> lock(m_mu);
        std::string cmd = "\"" + m_exePath + "\"";
        if (!m_args.empty()) {
            cmd += " ";
            cmd += m_args;
        }
        std::vector<char> cmdBuf(cmd.begin(), cmd.end());
        cmdBuf.push_back('\0');
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        ZeroMemory(&m_pi, sizeof(m_pi));
        const char* cwdPtr = m_cwd.empty() ? nullptr : m_cwd.c_str();
        const BOOL ok = CreateProcessA(
            m_exePath.c_str(), cmdBuf.data(), nullptr, nullptr, FALSE,
            DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, nullptr, cwdPtr, &si,
            &m_pi);
        if (!ok) {
            m_state = NativeDebugState::Error;
            m_stopReason = "CreateProcess DEBUG_ONLY_THIS_PROCESS failed";
            m_running = false;
            publishState(m_stopReason);
            return;
        }
    }

    DEBUG_EVENT ev{};
    while (true) {
        {
            std::lock_guard<std::mutex> lock(m_mu);
            if (m_stopRequested && m_state == NativeDebugState::Terminated) {
                break;
            }
        }
        const BOOL got = WaitForDebugEvent(&ev, 200);
        if (!got) {
            std::lock_guard<std::mutex> lock(m_mu);
            if (m_stopRequested && !m_pi.hProcess) {
                break;
            }
            DWORD code = 0;
            if (m_pi.hProcess && GetExitCodeProcess(m_pi.hProcess, &code) && code != STILL_ACTIVE) {
                m_exitCode = code;
                m_state = NativeDebugState::Terminated;
                m_stopReason = "process_exit_polled";
                publishState(m_stopReason);
                break;
            }
            continue;
        }

        {
            std::unique_lock<std::mutex> lock(m_mu);
            handleDebugEvent(ev);
        }

        // Wait until UI continues when paused.
        for (;;) {
            bool doContinue = false;
            DWORD status = DBG_CONTINUE;
            NativeDebugState st = NativeDebugState::Idle;
            {
                std::lock_guard<std::mutex> lock(m_mu);
                st = m_state;
                if (m_state == NativeDebugState::Paused && !m_pendingContinue) {
                    // wait for continue/step
                } else if (m_pendingContinue || m_state == NativeDebugState::Running ||
                           m_state == NativeDebugState::Stepping ||
                           m_state == NativeDebugState::Launching ||
                           m_state == NativeDebugState::Terminated ||
                           m_state == NativeDebugState::Idle ||
                           m_state == NativeDebugState::Error) {
                    doContinue = true;
                    status = m_continueStatus;
                    m_pendingContinue = false;
                }
                if (m_stopRequested && m_state != NativeDebugState::Paused) {
                    doContinue = true;
                    status = DBG_CONTINUE;
                }
            }
            if (doContinue || st == NativeDebugState::Terminated) {
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
                break;
            }
            Sleep(10);
        }

        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            break;
        }
    }

    std::lock_guard<std::mutex> lock(m_mu);
    m_running = false;
    if (m_state != NativeDebugState::Terminated) {
        m_state = NativeDebugState::Terminated;
    }
}

void Win32NativeDebugBackend::handleDebugEvent(const DEBUG_EVENT& ev) {
    m_continueStatus = DBG_CONTINUE;
    m_activeTid = ev.dwThreadId;

    auto findThread = [&](DWORD tid) -> HANDLE {
        for (auto& t : m_threads) {
            if (t.tid == tid && t.alive) {
                return t.handle;
            }
        }
        return nullptr;
    };

    switch (ev.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT: {
        m_imageBase = reinterpret_cast<uint64_t>(ev.u.CreateProcessInfo.lpBaseOfImage);
        NativeDebugThreadInfo t;
        t.tid = ev.dwThreadId;
        t.handle = ev.u.CreateProcessInfo.hThread;
        t.alive = true;
        m_threads.push_back(t);
        m_activeThread = t.handle;
        if (ev.u.CreateProcessInfo.hFile) {
            CloseHandle(ev.u.CreateProcessInfo.hFile);
        }
        resolveExportsFromImage();
        m_state = NativeDebugState::Running;
        if (m_onOutput) {
            m_onOutput("[native-debug] CREATE_PROCESS imageBase resolved exports=" +
                       std::to_string(m_exports.size()));
        }
        // Break on initial process breakpoint (system) then continue automatically
        // unless user BPs already planted — keep running after loader BP.
        m_pendingContinue = true;
        break;
    }
    case CREATE_THREAD_DEBUG_EVENT: {
        NativeDebugThreadInfo t;
        t.tid = ev.dwThreadId;
        t.handle = ev.u.CreateThread.hThread;
        t.alive = true;
        m_threads.push_back(t);
        m_pendingContinue = true;
        break;
    }
    case EXIT_THREAD_DEBUG_EVENT: {
        for (auto& t : m_threads) {
            if (t.tid == ev.dwThreadId) {
                t.alive = false;
            }
        }
        m_pendingContinue = true;
        break;
    }
    case EXIT_PROCESS_DEBUG_EVENT: {
        m_exitCode = ev.u.ExitProcess.dwExitCode;
        m_state = NativeDebugState::Terminated;
        m_stopReason = "exit_process";
        if (m_onOutput) {
            m_onOutput(std::string("[native-debug] EXIT_PROCESS code=") +
                       std::to_string(m_exitCode));
        }
        publishState(m_stopReason);
        m_pendingContinue = true;
        break;
    }
    case LOAD_DLL_DEBUG_EVENT: {
        if (ev.u.LoadDll.hFile) {
            CloseHandle(ev.u.LoadDll.hFile);
        }
        m_pendingContinue = true;
        break;
    }
    case UNLOAD_DLL_DEBUG_EVENT:
        m_pendingContinue = true;
        break;
    case OUTPUT_DEBUG_STRING_EVENT: {
        const auto& o = ev.u.DebugString;
        if (o.lpDebugStringData && o.nDebugStringLength > 0 && m_pi.hProcess) {
            std::string text(o.nDebugStringLength, '\0');
            SIZE_T got = 0;
            if (ReadProcessMemory(m_pi.hProcess, o.lpDebugStringData, text.data(),
                                  o.nDebugStringLength, &got)) {
                text.resize(got);
                while (!text.empty() && (text.back() == '\0' || text.back() == '\n' ||
                                         text.back() == '\r')) {
                    text.pop_back();
                }
                if (m_onOutput) {
                    m_onOutput(std::string("[debuggee] ") + text);
                }
            }
        }
        m_pendingContinue = true;
        break;
    }
    case EXCEPTION_DEBUG_EVENT: {
        const auto& ex = ev.u.Exception.ExceptionRecord;
        m_activeThread = findThread(ev.dwThreadId);
        if (!m_activeThread && m_pi.hThread) {
            m_activeThread = m_pi.hThread;
        }
        CONTEXT ctx{};
        if (getContext(ctx)) {
            m_currentRip = ctx.Rip;
            m_currentRsp = ctx.Rsp;
        }

        if (ex.ExceptionCode == EXCEPTION_BREAKPOINT) {
            uint64_t hitAddr = reinterpret_cast<uint64_t>(ex.ExceptionAddress);
            // INT3 stops after instruction; rewind RIP for software BP.
            if (ctx.Rip == hitAddr + 1 || ctx.Rip == hitAddr) {
                const uint64_t bpAddr = (ctx.Rip == hitAddr + 1) ? hitAddr : ctx.Rip;
                if (auto* bp = findBpByAddress(bpAddr)) {
                    restoreBreakpoint(*bp);
                    ctx.Rip = bpAddr;
                    setContext(ctx);
                    m_currentRip = bpAddr;
                    bp->hitCount++;
                    m_state = NativeDebugState::Paused;
                    m_pendingContinue = false;
                    publishState(std::string("breakpoint:") + bp->label);
                    if (m_onOutput) {
                        m_onOutput(std::string("[native-debug] BP hit ") + bp->label +
                                   " rip=0x" + [&]() {
                                       char b[32];
                                       std::snprintf(b, sizeof(b), "%llX",
                                                     static_cast<unsigned long long>(bpAddr));
                                       return std::string(b);
                                   }());
                    }
                    break;
                }
            }
            // Initial loader breakpoint or unknown — continue.
            m_pendingContinue = true;
            break;
        }

        if (ex.ExceptionCode == EXCEPTION_SINGLE_STEP) {
            setTrapFlag(false);
            // Re-apply BPs after step.
            for (auto& bp : m_bps) {
                if (bp.enabled) {
                    applyBreakpoint(bp);
                }
            }
            // Remove one-shot step_over/out markers at current RIP.
            m_bps.erase(std::remove_if(m_bps.begin(), m_bps.end(),
                                       [&](NativeDebugBp& bp) {
                                           if ((bp.label == "step_over_return" ||
                                                bp.label == "step_out_return") &&
                                               bp.address == m_currentRip) {
                                               restoreBreakpoint(bp);
                                               return true;
                                           }
                                           return false;
                                       }),
                        m_bps.end());
            m_expectStep = false;
            m_state = NativeDebugState::Paused;
            m_pendingContinue = false;
            publishState("step");
            break;
        }

        // Other exceptions: pause and report.
        m_state = NativeDebugState::Paused;
        m_pendingContinue = false;
        m_continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        publishState(formatException(ex.ExceptionCode));
        if (m_onOutput) {
            m_onOutput(std::string("[native-debug] ") + formatException(ex.ExceptionCode));
        }
        break;
    }
    default:
        m_pendingContinue = true;
        break;
    }
}

}  // namespace rawrxd
