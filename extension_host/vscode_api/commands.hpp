// commands.hpp — VS Code Commands API
#pragma once
#include <string>
#include <map>
#include <functional>
#include <any>

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

using CommandCallback = std::function<void(const std::vector<std::any>& args)>;

class Commands {
public:
    static Commands& Get();

    void Register(const std::string& id, CommandCallback fn);
    void Execute(const std::string& id, const std::vector<std::any>& args = {});
    bool Has(const std::string& id) const;
    void Dispose(const std::string& id);

private:
    Commands() = default;
    std::map<std::string, CommandCallback> m_commands;
};

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
