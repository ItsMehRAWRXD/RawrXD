// Standalone extension command-registry smoke. Not a QuickJS or VSIX certification.
// c++ -std=c++17 -pthread tests/extension_command_registry_smoke.cpp -o extension_registry_smoke
#include "../~dev/rawrxd/src/core/extension_host_production.cpp"
#include <cassert>
#include <stdexcept>
#include <string>
int main() {
    using RawrXD::Extensions::ExtensionHost;
    auto& host = ExtensionHost::GetInstance();
    host.Shutdown();
    assert(!host.RegisterCommand("preinit", [](const std::string&) { return true; }));
    assert(!host.ExecuteCommand("missing", ""));
    assert(!ExtensionHost::ValidCommandName(""));
    assert(!ExtensionHost::ValidCommandName("bad\nname"));
    assert(!ExtensionHost::ValidCommandName(std::string(257, 'x')));
    assert(host.Initialize());
    int count = 0;
    assert(host.RegisterExtensionCommand("ext.one", "ext.run",
        [&](const std::string& arg) { ++count; return arg == "ok"; }));
    assert(!host.RegisterExtensionCommand("ext.two", "ext.run",
        [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("bad id", "bad.run",
        [](const std::string&) { return true; }));
    assert(host.ExecuteCommand("ext.run", "ok"));
    assert(!host.ExecuteCommand("ext.run", "bad"));
    assert(count == 2);
    assert(host.RegisterCommand("throw", [](const std::string&) -> bool {
        throw std::runtime_error("injected failure");
    }));
    assert(!host.ExecuteCommand("throw", ""));
    assert(host.RegisterCommand("nested", [&](const std::string&) {
        return host.RegisterCommand("nested.created", [](const std::string&) { return true; });
    }));
    assert(host.ExecuteCommand("nested", ""));
    assert(host.ExecuteCommand("nested.created", ""));
    host.UnregisterExtensionCommands("ext.two");
    assert(host.ExecuteCommand("ext.run", "ok"));
    host.UnregisterExtensionCommands("ext.one");
    assert(!host.ExecuteCommand("ext.run", "ok"));
    assert(host.UnregisterCommand("nested.created"));
    assert(!host.UnregisterCommand("nested.created"));
    host.Shutdown();
    assert(!host.IsInitialized());
    assert(host.GetAvailableCommands().empty());
    assert(!host.ExecuteCommand("throw", ""));
    assert(host.Initialize());
    assert(!host.ExecuteCommand("throw", ""));
    host.Shutdown();
    return 0;
}
