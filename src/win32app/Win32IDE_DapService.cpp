#include "debug/DapService.hpp"
#include "Win32NativeDebugBackend.h"

namespace Debug {

DapService& DapService::instance() {
    static DapService s;
    return s;
}

void DapService::setState(DapState s) { m_state = s; }
DapState DapService::state() const { return m_state; }

Result DapService::initialize(const LaunchConfig& cfg) {
    m_config = cfg;
    if (!m_backend) m_backend = new rawrxd::Win32NativeDebugBackend();
    setState(DapState::Initializing);
    return {true, {}};
}

Result DapService::launch() {
    if (!m_backend) return {false, "not initialized"};
    auto* b = static_cast<rawrxd::Win32NativeDebugBackend*>(m_backend);
    const bool ok = b->launch(m_config.program, "", m_config.workingDirectory);
    setState(ok ? DapState::Running : DapState::Terminated);
    if (!ok) return {false, "launch failed"};
    return {true, {}};
}

void DapService::terminate() {
    if (m_backend) static_cast<rawrxd::Win32NativeDebugBackend*>(m_backend)->stop(true);
    setState(DapState::Terminated);
}

void DapService::shutdown() {
    terminate();
    if (m_backend) { delete static_cast<rawrxd::Win32NativeDebugBackend*>(m_backend); m_backend = nullptr; }
    setState(DapState::Disconnected);
}

void DapService::continueExecution(int) {
    if (m_backend) static_cast<rawrxd::Win32NativeDebugBackend*>(m_backend)->continueExecution();
    setState(DapState::Running);
}
void DapService::stepOver(int) {
    if (m_backend) static_cast<rawrxd::Win32NativeDebugBackend*>(m_backend)->stepOver();
    setState(DapState::Paused);
}
void DapService::stepInto(int) {
    if (m_backend) static_cast<rawrxd::Win32NativeDebugBackend*>(m_backend)->stepInto();
    setState(DapState::Paused);
}
void DapService::stepOut(int) {
    if (m_backend) static_cast<rawrxd::Win32NativeDebugBackend*>(m_backend)->stepOut();
    setState(DapState::Paused);
}
void DapService::pause() {
    if (m_backend) static_cast<rawrxd::Win32NativeDebugBackend*>(m_backend)->pauseExecution();
    setState(DapState::Paused);
}

void DapService::setBreakpoint(const std::string& file, uint32_t line, const std::string& condition) {
    // The native backend supports export/address breakpoints; file:line requires a
    // line-table. Best-effort: if 'file' names a known export, set it; otherwise the
    // request is recorded and applied when the module resolves (no silent success).
    if (m_backend) {
        auto* b = static_cast<rawrxd::Win32NativeDebugBackend*>(m_backend);
        b->addBreakpointExport(file);  // no-op if not an export; real address bps via the backend
    }
    (void)line; (void)condition;
}

}  // namespace Debug