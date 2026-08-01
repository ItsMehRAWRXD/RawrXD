// debug_api.hpp — VS Code Debug API
#pragma once
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

struct DebugConfiguration {
    std::string type;
    std::string name;
    std::string request; // "launch" or "attach"
    std::string program;
    std::string args;
    std::string cwd;
    std::string runtimeExecutable;
    std::string stopOnEntry;
};

struct Breakpoint {
    std::string filePath;
    int line = 0;
    bool enabled = true;
    std::string condition;
    std::string hitCondition;
};

class Debug {
public:
    static Debug& Get();

    // Configuration
    void RegisterDebugConfigurationProvider(const std::string& type, 
        std::function<std::vector<DebugConfiguration>()> provider);
    std::vector<DebugConfiguration> GetConfigurations(const std::string& type);

    // Breakpoints
    void SetBreakpoints(const std::string& filePath, const std::vector<Breakpoint>& breakpoints);
    std::vector<Breakpoint> GetBreakpoints(const std::string& filePath) const;
    void RemoveBreakpoints(const std::string& filePath);

    // Session
    bool StartDebugging(const DebugConfiguration& config);
    bool StopDebugging();
    bool IsDebugging() const { return m_debugging; }

    // Events
    using DebugCallback = std::function<void(const std::string& event)>;
    void OnDidStartDebugSession(DebugCallback callback) { m_onStart = callback; }
    void OnDidTerminateDebugSession(DebugCallback callback) { m_onTerminate = callback; }

private:
    Debug() = default;
    std::map<std::string, std::function<std::vector<DebugConfiguration>()>> m_providers;
    std::map<std::string, std::vector<Breakpoint>> m_breakpoints;
    bool m_debugging = false;
    DebugCallback m_onStart;
    DebugCallback m_onTerminate;
};

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
