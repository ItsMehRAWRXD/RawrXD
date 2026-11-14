// Win32NativeDebugBackend.h — WaitForDebugEvent product backend (C39/C40).
// PROMOTE=0 · SOURCE_WIRED != RUNTIME_REACHED · no invent PASS.
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef kRawrxdNativeDebugState
constexpr UINT kRawrxdNativeDebugState = WM_APP + 0x60;
#endif

namespace rawrxd {

enum class NativeDebugState : int {
    Idle = 0,
    Starting,
    Running,
    Paused,
    Stepping,
    Terminated
};

struct NativeDebugStackFrame {
    uint64_t rip = 0;
    uint64_t rsp = 0;
    std::string name;
};

struct NativeDebugSnapshot {
    NativeDebugState state = NativeDebugState::Idle;
    DWORD pid = 0;
    DWORD exitCode = 0;
    uint64_t rip = 0;
    std::string stopReason;
    std::vector<NativeDebugStackFrame> stack;
    std::map<std::string, std::string> variables;
};

class NativeDebugBackend {
public:
    NativeDebugBackend();
    ~NativeDebugBackend();
    NativeDebugBackend(const NativeDebugBackend&) = delete;
    NativeDebugBackend& operator=(const NativeDebugBackend&) = delete;

    void setNotifyHwnd(HWND hwnd);
    bool addBreakpointExport(const std::string& exportName);
    bool launch(const std::string& exePath, const std::string& args = "");
    bool continueExecution();
    void stop();

    NativeDebugSnapshot snapshot() const;
    NativeDebugState state() const;
    DWORD lastExitCode() const;

private:
    void pumpThreadMain();
    void publishLocked();
    bool resolveExportVa(HANDLE proc, uint64_t imageBase, const char* name,
                         uint64_t* outVa) const;
    void capturePausedLocked(DWORD tid);

    HWND m_notify = nullptr;
    mutable std::mutex m_mu;
    NativeDebugSnapshot m_snap;
    std::string m_bpExport = "break_site";
    PROCESS_INFORMATION m_pi{};
    DEBUG_EVENT m_ev{};
    uint64_t m_bpVa = 0;
    uint64_t m_watchVa = 0;
    BYTE m_origByte = 0x90;
    bool m_bpArmed = false;
    bool m_active = false;
    bool m_stopReq = false;
    bool m_resumeReq = false;
    std::string m_launchExe;
    std::string m_launchArgs;
    std::thread m_thr;
};

}  // namespace rawrxd
