#pragma once
// Product native debug backend: WaitForDebugEvent + CreateProcess(DEBUG_*).
// Not a UI mock. DbgEng is not required for this path.

#ifndef RAWRXD_WIN32_NATIVE_DEBUG_BACKEND_H
#define RAWRXD_WIN32_NATIVE_DEBUG_BACKEND_H

#include <windows.h>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace rawrxd {

enum class NativeDebugState : uint32_t {
    Idle = 0,
    Launching,
    Running,
    Paused,
    Stepping,
    Terminated,
    Error
};

struct NativeDebugBp {
    uint64_t address = 0;
    uint8_t original = 0;
    bool enabled = true;
    bool applied = false;
    uint32_t hitCount = 0;
    std::string label;
};

struct NativeDebugFrame {
    uint64_t rip = 0;
    uint64_t rsp = 0;
    std::string module;
    std::string symbol;
};

struct NativeDebugThreadInfo {
    DWORD tid = 0;
    HANDLE handle = nullptr;
    bool alive = true;
};

struct NativeDebugSnapshot {
    NativeDebugState state = NativeDebugState::Idle;
    DWORD pid = 0;
    DWORD exitCode = 0;
    uint64_t rip = 0;
    uint64_t rsp = 0;
    uint64_t imageBase = 0;
    std::string stopReason;
    std::vector<NativeDebugFrame> stack;
    std::vector<NativeDebugThreadInfo> threads;
    std::map<std::string, uint64_t> exports;
    std::map<std::string, std::string> variables;
};

class Win32NativeDebugBackend {
public:
    using OutputFn = std::function<void(const std::string&)>;
    using StateFn = std::function<void(const NativeDebugSnapshot&)>;

    Win32NativeDebugBackend();
    ~Win32NativeDebugBackend();

    Win32NativeDebugBackend(const Win32NativeDebugBackend&) = delete;
    Win32NativeDebugBackend& operator=(const Win32NativeDebugBackend&) = delete;

    void setOutputCallback(OutputFn fn);
    void setStateCallback(StateFn fn);

    bool launch(const std::string& exePath,
                const std::string& args = {},
                const std::string& workingDir = {});
    bool stop(bool terminate = true);
    bool restart();
    bool continueExecution();
    bool pauseExecution();
    bool stepInto();
    bool stepOver();
    bool stepOut();

    bool addBreakpointExport(const std::string& exportName);
    bool addBreakpointAddress(uint64_t address, const std::string& label = {});
    bool removeBreakpointAddress(uint64_t address);
    bool clearBreakpoints();

    bool readMemory(uint64_t address, void* buffer, size_t size) const;
    bool evaluateExpression(const std::string& expression, std::string& outValue) const;
    NativeDebugSnapshot snapshot() const;
    NativeDebugState state() const;
    DWORD lastExitCode() const { return m_exitCode; }
    bool isActive() const;

private:
    void eventThreadMain();
    void handleDebugEvent(const DEBUG_EVENT& ev);
    void publishState(const std::string& reason);
    bool applyBreakpoint(NativeDebugBp& bp);
    bool restoreBreakpoint(NativeDebugBp& bp);
    bool setTrapFlag(bool enable);
    bool getContext(CONTEXT& ctx) const;
    bool setContext(const CONTEXT& ctx) const;
    bool resolveExportsFromImage();
    bool walkStackUnlocked(std::vector<NativeDebugFrame>& out) const;
    bool refreshVariablesUnlocked();
    NativeDebugBp* findBpByAddress(uint64_t address);
    bool addBreakpointAddressUnlocked(uint64_t address, const std::string& label);
    bool stepIntoUnlocked();
    void cleanupHandles();
    std::string formatException(DWORD code) const;

    mutable std::mutex m_mu;
    OutputFn m_onOutput;
    StateFn m_onState;

    NativeDebugState m_state = NativeDebugState::Idle;
    std::string m_exePath;
    std::string m_args;
    std::string m_cwd;

    PROCESS_INFORMATION m_pi{};
    DWORD m_exitCode = 0;
    uint64_t m_imageBase = 0;
    HANDLE m_activeThread = nullptr;
    DWORD m_activeTid = 0;
    uint64_t m_currentRip = 0;
    uint64_t m_currentRsp = 0;
    std::string m_stopReason;

    std::vector<NativeDebugBp> m_bps;
    std::vector<NativeDebugThreadInfo> m_threads;
    std::map<std::string, uint64_t> m_exports;
    std::map<std::string, std::string> m_variables;

    std::thread m_thread;
    bool m_running = false;
    bool m_stopRequested = false;
    bool m_expectStep = false;
    bool m_pendingContinue = false;
    bool m_breakOnNext = false;
    DWORD m_continueStatus = DBG_CONTINUE;
};

}  // namespace rawrxd

#endif
