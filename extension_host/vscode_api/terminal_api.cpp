// terminal_api.cpp — VS Code Terminal API Implementation
#include "terminal_api.hpp"
#include <algorithm>

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

Terminal::~Terminal() {
    Dispose();
}

void Terminal::SendText(const std::string& text) {
    // TODO: Write to PTY
}

void Terminal::SendTextAndNewLine(const std::string& text) {
    SendText(text + "\n");
}

void Terminal::Show() {
    m_visible = true;
}

void Terminal::Hide() {
    m_visible = false;
}

void Terminal::Dispose() {
    if (m_ptyHandle) {
        // TODO: Close PTY handle
        m_ptyHandle = nullptr;
    }
}

TerminalManager& TerminalManager::Get() {
    static TerminalManager instance;
    return instance;
}

Terminal* TerminalManager::CreateTerminal(const std::string& name) {
    auto* terminal = new Terminal(name);
    m_terminals.push_back(terminal);
    m_activeTerminal = terminal;
    return terminal;
}

void TerminalManager::DisposeTerminal(Terminal* terminal) {
    auto it = std::find(m_terminals.begin(), m_terminals.end(), terminal);
    if (it != m_terminals.end()) {
        if (m_activeTerminal == terminal) {
            m_activeTerminal = m_terminals.size() > 1 ? m_terminals[0] : nullptr;
            if (m_activeTerminal == terminal) m_activeTerminal = nullptr;
        }
        m_terminals.erase(it);
        delete terminal;
    }
}

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
