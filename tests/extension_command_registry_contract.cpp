// Headless contract tests for the local extension command registry.
// Build from repository root:
//   c++ -std=c++17 -pthread tests/extension_command_registry_contract.cpp -o extension_registry_test
//   ./extension_registry_test
// This tests the registry, NOT the QuickJS/VSIX runtime or Win32 GUI.
#include <cassert>
#include <stdexcept>
#include <string>
#include <vector>
#include "../~dev/rawrxd/src/core/extension_host_production.cpp"

int main() {
    using RawrXD::Extensions::ExtensionHost;
    auto& host = ExtensionHost::GetInstance();
    host.Shutdown();
    assert(!host.IsInitialized());
    assert(!host.RegisterCommand("before-init", [](const std::string&) { return true; }));
    assert(!host.ExecuteCommand("missing", ""));
    assert(host.Initialize());
    assert(host.IsInitialized());
    assert(!host.RegisterCommand("", [](const std::string&) { return true; }));
    assert(!host.RegisterCommand("null-handler", {}));
    assert(!host.RegisterExtensionCommand("", "invalid", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("ext", "", [](const std::string&) { return true; }));

    int calls = 0;
    assert(host.RegisterCommand("host", [&](const std::string& s) {
        ++calls;
        return s == "ok";
    }));
    assert(!host.RegisterCommand("host", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("ext", "host", [](const std::string&) { return true; }));
    assert(host.ExecuteCommand("host", "ok"));
    assert(!host.ExecuteCommand("host", "bad"));
    assert(calls == 2);

    assert(host.RegisterExtensionCommand("ext-A", "owned-A", [&](const std::string&) {
        return host.ExecuteCommand("host", "ok"); // nested dispatch must not deadlock
    }));
    assert(host.RegisterExtensionCommand("ext-B", "owned-B", [](const std::string&) { return true; }));
    assert(host.ExecuteCommand("owned-A", ""));
    assert(calls == 3);
    assert(host.RegisterCommand("throws", [](const std::string&) -> bool {
        throw std::runtime_error("extension failure");
    }));
    assert(!host.ExecuteCommand("throws", ""));
    assert(!host.ExecuteCommand("unknown", ""));

    auto names = host.GetAvailableCommands();
    assert(names.size() == 4);
    host.UnregisterExtensionCommands("ext-A");
    assert(!host.ExecuteCommand("owned-A", ""));
    assert(host.ExecuteCommand("owned-B", ""));
    assert(!host.UnregisterCommand("owned-A"));
    assert(host.UnregisterCommand("owned-B"));
    assert(host.UnregisterCommand("host"));
    assert(host.UnregisterCommand("throws"));
    assert(host.GetAvailableCommands().empty());

    host.Shutdown();
    assert(!host.IsInitialized());
    assert(!host.ExecuteCommand("host", "ok"));
    assert(host.GetAvailableCommands().empty());
    assert(host.Initialize());
    assert(host.GetAvailableCommands().empty());
    host.Shutdown();
    return 0;
}
