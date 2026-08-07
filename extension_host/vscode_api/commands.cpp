// commands.cpp — VS Code Commands API Implementation
#include "commands.hpp"

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

Commands& Commands::Get() {
    static Commands instance;
    return instance;
}

void Commands::Register(const std::string& id, CommandCallback fn) {
    m_commands[id] = std::move(fn);
}

void Commands::Execute(const std::string& id, const std::vector<std::any>& args) {
    auto it = m_commands.find(id);
    if (it != m_commands.end()) {
        it->second(args);
    }
}

bool Commands::Has(const std::string& id) const {
    return m_commands.find(id) != m_commands.end();
}

void Commands::Dispose(const std::string& id) {
    m_commands.erase(id);
}

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
