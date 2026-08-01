// terminal_api.hpp — VS Code Terminal API
#pragma once
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

class Terminal {
public:
    Terminal(const std::string& name) : m_name(name) {}
    ~Terminal();

    std::string GetName() const { return m_name; }
    void SendText(const std::string& text);
    void SendTextAndNewLine(const std::string& text);
    void Show();
    void Hide();
    void Dispose();
    bool IsVisible() const { return m_visible; }
    int GetProcessId() const { return m_processId; }

    // Output callback
    using OutputCallback = std::function<void(const std::string& output)>;
    void OnDidWriteData(OutputCallback callback) { m_onOutput = callback; }

private:
    std::string m_name;
    bool m_visible = false;
    int m_processId = -1;
    OutputCallback m_onOutput;
    void* m_ptyHandle = nullptr;
};

class TerminalManager {
public:
    static TerminalManager& Get();

    Terminal* CreateTerminal(const std::string& name);
    Terminal* GetActiveTerminal() const { return m_activeTerminal; }
    std::vector<Terminal*> GetTerminals() const { return m_terminals; }
    void DisposeTerminal(Terminal* terminal);

private:
    TerminalManager() = default;
    Terminal* m_activeTerminal = nullptr;
    std::vector<Terminal*> m_terminals;
};

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
