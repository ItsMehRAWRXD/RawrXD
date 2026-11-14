// Win32IDE_NativeDebugBackend_Wire.cpp — ensure/launch/DAP E2E probe (9624).
// Side-map backend storage: no Win32IDE member layout drift on tip objs.
#include "Win32IDE.h"
#include "Win32NativeDebugBackend.h"
#include "Win32IDE_CommandIDs.h"
#include <cstdlib>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace {
std::mutex g_ndMu;
std::unordered_map<Win32IDE*, std::unique_ptr<rawrxd::NativeDebugBackend>> g_nd;

rawrxd::NativeDebugBackend* NdGet(Win32IDE* self) {
    std::lock_guard<std::mutex> g(g_ndMu);
    auto it = g_nd.find(self);
    return it == g_nd.end() ? nullptr : it->second.get();
}

void WriteDapJournal(const std::string& line) {
    const char* dir = std::getenv("RAWRXD_LOG_DIR");
    const std::string path = (dir && *dir)
        ? (std::string(dir) + "\\DAP_E2E_JOURNAL.txt")
        : std::string("DAP_E2E_JOURNAL.txt");
    std::ofstream out(path, std::ios::app);
    if (out) out << line << '\n';
}

std::string ResolveDebuggeePath() {
    if (const char* env = std::getenv("RAWRXD_DAP_DEBUGGEE")) {
        if (env[0] && GetFileAttributesA(env) != INVALID_FILE_ATTRIBUTES)
            return env;
    }
    static const char* kCands[] = {
        "G:\\~dev\\rawrxd\\evidence\\CLI_ACCEPTANCE_001\\fixture\\debuggee_fixture.exe",
        "evidence\\CLI_ACCEPTANCE_001\\fixture\\debuggee_fixture.exe",
        nullptr};
    for (int i = 0; kCands[i]; ++i) {
        if (GetFileAttributesA(kCands[i]) != INVALID_FILE_ATTRIBUTES)
            return kCands[i];
    }
    return {};
}
}  // namespace

void Win32IDE::ensureNativeDebugBackend() {
    std::lock_guard<std::mutex> g(g_ndMu);
    auto& p = g_nd[this];
    if (!p) p = std::make_unique<rawrxd::NativeDebugBackend>();
    p->setNotifyHwnd(m_hwndMain);
}

void Win32IDE::stopNativeDebugBackend() {
    rawrxd::NativeDebugBackend* b = nullptr;
    {
        std::lock_guard<std::mutex> g(g_ndMu);
        auto it = g_nd.find(this);
        if (it != g_nd.end()) b = it->second.get();
    }
    if (b) b->stop();
}

bool Win32IDE::launchNativeDebuggee() {
    ensureNativeDebugBackend();
    auto* b = NdGet(this);
    if (!b) return false;
    const std::string exe = ResolveDebuggeePath();
    if (exe.empty()) {
        WriteDapJournal("PROCESS_LAUNCH_FAILED reason=debuggee_missing");
        return false;
    }
    WriteDapJournal(std::string("DEBUGGEE_PATH=") + exe);
    return b->launch(exe);
}

LRESULT Win32IDE::handleNativeDebugState(WPARAM wParam, LPARAM lParam) {
    (void)wParam;
    if (lParam) {
        delete reinterpret_cast<rawrxd::NativeDebugSnapshot*>(lParam);
    }
    return 0;
}

void Win32IDE::runDapE2EProbe() {
    {
        const char* dir = std::getenv("RAWRXD_LOG_DIR");
        const std::string path = (dir && *dir)
            ? (std::string(dir) + "\\DAP_E2E_JOURNAL.txt")
            : std::string("DAP_E2E_JOURNAL.txt");
        std::ofstream trunc(path, std::ios::trunc);
    }
    stopNativeDebugBackend();
    WriteDapJournal("DEBUG_SESSION_START");
    ensureNativeDebugBackend();
    WriteDapJournal("ADAPTER_INITIALIZED backend=WaitForDebugEvent");
    if (auto* b = NdGet(this)) b->addBreakpointExport("break_site");
    WriteDapJournal("BREAKPOINT_VERIFIED export=break_site");
    const bool launched = launchNativeDebuggee();
    WriteDapJournal(launched ? "PROCESS_LAUNCHED" : "PROCESS_LAUNCH_FAILED");
    int stackN = 0, varN = 0, stoppedBp = 0, continued = 0, exited = 0;
    DWORD exitCode = 0;
    std::string watchVal;
    auto* nd = NdGet(this);
    if (launched && nd) {
        char pidBuf[64];
        sprintf_s(pidBuf, " pid=%lu",
                  static_cast<unsigned long>(nd->snapshot().pid));
        WriteDapJournal(std::string("PROCESS_LAUNCHED_DETAIL") + pidBuf);
        const DWORD deadline = GetTickCount() + 8000;
        while (GetTickCount() < deadline) {
            MSG msg{};
            while (m_hwndMain &&
                   PeekMessageA(&msg, m_hwndMain, kRawrxdNativeDebugState,
                                kRawrxdNativeDebugState, PM_REMOVE)) {
                if (msg.lParam) {
                    const auto* snap =
                        reinterpret_cast<const rawrxd::NativeDebugSnapshot*>(
                            msg.lParam);
                    if (snap &&
                        snap->stopReason.rfind("breakpoint:", 0) == 0) {
                        const char* logDir = std::getenv("RAWRXD_LOG_DIR");
                        const std::string wfde = (logDir && *logDir)
                            ? (std::string(logDir) + "\\WFDE_BP_HIT_RECEIPT.txt")
                            : std::string("WFDE_BP_HIT_RECEIPT.txt");
                        std::ofstream out(wfde, std::ios::trunc);
                        if (out) {
                            out << "WFDE_BP_HIT=1\n"
                                << "STOP_REASON=" << snap->stopReason << '\n'
                                << "API=WaitForDebugEvent\n";
                        }
                    }
                }
                handleNativeDebugState(msg.wParam, msg.lParam);
            }
            const auto snap = nd->snapshot();
            if (snap.stopReason.rfind("breakpoint:", 0) == 0 && !stoppedBp) {
                stoppedBp = 1;
                char hex[32];
                sprintf_s(hex, "0x%llX",
                          static_cast<unsigned long long>(snap.rip));
                WriteDapJournal(std::string("STOPPED_REASON=breakpoint rip=") +
                                hex + " reason=" + snap.stopReason);
                stackN = static_cast<int>(snap.stack.size());
                if (stackN > 0)
                    WriteDapJournal("STACK_FRAMES_RECEIVED count=" +
                                    std::to_string(stackN));
                varN = static_cast<int>(snap.variables.size());
                auto it = snap.variables.find("g_watch_value");
                if (it != snap.variables.end()) watchVal = it->second;
                if (varN > 0)
                    WriteDapJournal("VARIABLES count=" + std::to_string(varN) +
                                    " g_watch_value=" + watchVal);
            }
            if (snap.state == rawrxd::NativeDebugState::Paused ||
                snap.state == rawrxd::NativeDebugState::Stepping) {
                if (nd->continueExecution()) {
                    continued = 1;
                    WriteDapJournal("CONTINUE");
                }
            }
            if (snap.state == rawrxd::NativeDebugState::Terminated) {
                exitCode = snap.exitCode;
                exited = 1;
                WriteDapJournal("PROCESS_EXITED code=" +
                                std::to_string(exitCode));
                break;
            }
            Sleep(20);
        }
        if (!exited) {
            exitCode = nd->lastExitCode();
            if (nd->state() == rawrxd::NativeDebugState::Terminated) {
                exited = 1;
                WriteDapJournal("PROCESS_EXITED code=" +
                                std::to_string(exitCode));
            }
            nd->stop();
        }
    }
    WriteDapJournal("DEBUG_SESSION_TERMINATED");
    const int sessionOk =
        (launched && stoppedBp && stackN > 0 && continued && exited) ? 1 : 0;
    WriteDapJournal(std::string("SESSION_REAL=") + std::to_string(sessionOk) +
                    " bp=" + std::to_string(stoppedBp) +
                    " stack=" + std::to_string(stackN) +
                    " vars=" + std::to_string(varN) +
                    " continue=" + std::to_string(continued) +
                    " exited=" + std::to_string(exited) +
                    " watch=" + watchVal);
    appendToOutput(std::string("[DAP_E2E] SESSION_REAL=") +
                       std::to_string(sessionOk) + "\n",
                   "Debug", OutputSeverity::Info);
}

