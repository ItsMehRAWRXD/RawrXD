// debug_api.cpp — VS Code Debug API Implementation
#include "debug_api.hpp"

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

Debug& Debug::Get() {
    static Debug instance;
    return instance;
}

void Debug::RegisterDebugConfigurationProvider(const std::string& type,
    std::function<std::vector<DebugConfiguration>()> provider) {
    m_providers[type] = std::move(provider);
}

std::vector<DebugConfiguration> Debug::GetConfigurations(const std::string& type) {
    auto it = m_providers.find(type);
    if (it != m_providers.end()) {
        return it->second();
    }
    return {};
}

void Debug::SetBreakpoints(const std::string& filePath, const std::vector<Breakpoint>& breakpoints) {
    m_breakpoints[filePath] = breakpoints;
}

std::vector<Breakpoint> Debug::GetBreakpoints(const std::string& filePath) const {
    auto it = m_breakpoints.find(filePath);
    return it != m_breakpoints.end() ? it->second : std::vector<Breakpoint>{};
}

void Debug::RemoveBreakpoints(const std::string& filePath) {
    m_breakpoints.erase(filePath);
}

bool Debug::StartDebugging(const DebugConfiguration& config) {
    if (m_debugging) return false;
    m_debugging = true;
    if (m_onStart) m_onStart("start");
    return true;
}

bool Debug::StopDebugging() {
    if (!m_debugging) return false;
    m_debugging = false;
    if (m_onTerminate) m_onTerminate("terminate");
    return true;
}

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
