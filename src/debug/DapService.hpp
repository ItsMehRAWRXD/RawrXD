#pragma once
// Debug::DapService — production DAP service backed by the real native debug
// backend (rawrxd::Win32NativeDebugBackend). No stubs: launch/step/continue/
// pause/stop/breakpoints/state are forwarded to the native backend.
#ifndef RAWRXD_IDE_DAP_SERVICE_H
#define RAWRXD_IDE_DAP_SERVICE_H

#include <cstdint>
#include <string>

namespace Debug {

enum class DapState { Disconnected, Initializing, Running, Paused, Stopped, Terminated };
inline const char* StateToString(DapState s) {
    switch (s) {
        case DapState::Initializing: return "Initializing";
        case DapState::Running:      return "Running";
        case DapState::Paused:       return "Paused";
        case DapState::Stopped:      return "Stopped";
        case DapState::Terminated:   return "Terminated";
        default:                     return "Disconnected";
    }
}

struct LaunchConfig {
    std::string program;
    std::string workingDirectory;
    std::string debuggerType = "cppvsdbg";
    bool stopOnEntry = false;
};

struct Result {
    bool ok = true;
    std::string error;
    explicit operator bool() const { return ok; }
};

class DapService {
public:
    static DapService& instance();

    Result initialize(const LaunchConfig& cfg);
    Result launch();
    void   terminate();
    void   shutdown();

    void continueExecution(int threadId);
    void stepOver(int threadId);
    void stepInto(int threadId);
    void stepOut(int threadId);
    void pause();
    void setBreakpoint(const std::string& file, uint32_t line, const std::string& condition);

    DapState state() const;

private:
    DapService() = default;
    void setState(DapState s);
    // Opaque backend pointer (avoids leaking the backend header into the public API).
    void* m_backend = nullptr;
    LaunchConfig m_config;
    DapState m_state = DapState::Disconnected;
};

}  // namespace Debug

#endif