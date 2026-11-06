// Native integration test: compiles the actual extension command bridge, no mocks.
#include "../../~dev/rawrxd/src/core/extension_host_production.cpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <stdexcept>
#include <string>
#include <vector>

int main() {
    auto& host = RawrXD::Extensions::ExtensionHost::GetInstance();
    host.Shutdown();
    assert(!host.IsInitialized());
    assert(!host.RegisterCommand("before-init", [](const std::string&) { return true; }));
    assert(!host.ExecuteCommand("missing", ""));
    assert(host.Initialize());
    assert(host.IsInitialized());
    assert(host.Initialize());
    assert(!host.RegisterCommand("", [](const std::string&) { return true; }));
    assert(!host.RegisterCommand("null-handler", {}));
    int calls = 0;
    assert(host.RegisterCommand("host-command", [&](const std::string& arg) {
        ++calls;
        return arg == "expected";
    }));
    assert(!host.RegisterCommand("host-command", [](const std::string&) { return true; }));
    assert(host.ExecuteCommand("host-command", "expected"));
    assert(calls == 1);
    assert(!host.ExecuteCommand("host-command", "other"));
    assert(calls == 2);
    assert(!host.RegisterExtensionCommand("", "bad", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("bad id", "bad", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("bad\\tid", "bad-tab", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("bad\\nid", "bad-newline", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("extension.one", "host-command", [](const std::string&) { return true; }));
    assert(host.RegisterExtensionCommand("extension.one", "extension-command", [&](const std::string&) {
        // Re-entrant unregister must not deadlock.
        host.UnregisterExtensionCommands("extension.one");
        return true;
    }));
    assert(host.ExecuteCommand("extension-command", ""));
    assert(!host.ExecuteCommand("extension-command", ""));
    assert(host.RegisterCommand("throwing", [](const std::string&) -> bool {
        throw std::runtime_error("expected");
    }));
    assert(!host.ExecuteCommand("throwing", ""));
    const auto available = host.GetAvailableCommands();
    assert(available.size() == 2);
    assert(host.UnregisterCommand("throwing"));
    assert(!host.UnregisterCommand("throwing"));
    host.Shutdown();
    assert(!host.IsInitialized());
    assert(host.GetAvailableCommands().empty());
    assert(!host.ExecuteCommand("host-command", ""));
    assert(host.Initialize());
    assert(host.GetAvailableCommands().empty());
    host.Shutdown();
}
