// Standalone regression gate for the native extension command bridge.
// Build: c++ -std=c++17 -pthread tests/extension_command_bridge_smoke.cpp -o extension_command_bridge_smoke
// No model, Ollama, Qt, or GPU required.
#include "../~dev/rawrxd/src/core/extension_host_production.cpp"
#include <cassert>
#include <stdexcept>
#include <string>
#include <vector>

int main() {
    using RawrXD::Extensions::ExtensionHost;
    auto& host = ExtensionHost::GetInstance();
    host.Shutdown();
    int calls = 0;
    // 1: no command registration before initialization.
    assert(!host.RegisterCommand("before", [](const std::string&) { return true; }));
    // 2: no dispatch before initialization.
    assert(!host.ExecuteCommand("missing", ""));
    // 3: initialization succeeds.
    assert(host.Initialize() && host.IsInitialized());
    // 4: malformed command names fail closed.
    assert(!host.RegisterCommand("", [](const std::string&) { return true; }));
    assert(!host.RegisterCommand("bad\nname", [](const std::string&) { return true; }));
    assert(!host.RegisterCommand(std::string(257, 'x'), [](const std::string&) { return true; }));
    // 5: empty callback is rejected.
    assert(!host.RegisterCommand("empty", {}));
    // 6: command is executed with exact arguments.
    assert(host.RegisterCommand("echo", [&](const std::string& arg) { ++calls; return arg == "payload"; }));
    assert(host.ExecuteCommand("echo", "payload") && calls == 1);
    // 7: duplicate command cannot override existing callback.
    assert(!host.RegisterCommand("echo", [](const std::string&) { return false; }));
    // 8: unknown commands fail.
    assert(!host.ExecuteCommand("unknown", ""));
    // 9: throwing callback fails closed without killing dispatch.
    assert(host.RegisterCommand("throw", [](const std::string&) -> bool { throw std::runtime_error("fixture"); }));
    assert(!host.ExecuteCommand("throw", ""));
    // 10: nested dispatch must not deadlock.
    assert(host.RegisterCommand("nested", [&](const std::string&) { return host.ExecuteCommand("echo", "payload"); }));
    assert(host.ExecuteCommand("nested", "") && calls == 2);
    // 11: extension ownership identifier is validated.
    assert(!host.RegisterExtensionCommand("", "badOwner", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("bad owner", "badOwner", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand(std::string("bad\0id", 6), "badOwner", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand(std::string(257, 'x'), "badOwner", [](const std::string&) { return true; }));
    // 12: extension command registration and execution.
    assert(host.RegisterExtensionCommand("ext.one", "owned", [](const std::string&) { return true; }));
    assert(host.ExecuteCommand("owned", ""));
    assert(host.RegisterExtensionCommand("ext.two", "otherOwned", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("ext.two", "owned", [](const std::string&) { return true; }));
    // 13: extension cleanup revokes its commands but preserves host commands.
    host.UnregisterExtensionCommands("ext.one");
    assert(!host.ExecuteCommand("owned", "") && host.ExecuteCommand("echo", "payload"));
    assert(host.ExecuteCommand("otherOwned", ""));
    // 14: explicit unregistration revokes dispatch.
    assert(host.UnregisterCommand("echo") && !host.ExecuteCommand("echo", ""));
    assert(!host.UnregisterCommand("echo"));
    // 15: shutdown clears state, and restart does not resurrect commands.
    host.Shutdown();
    assert(!host.IsInitialized() && host.GetAvailableCommands().empty());
    assert(!host.ExecuteCommand("nested", ""));
    assert(host.Initialize());
    assert(host.GetAvailableCommands().empty());
    host.Shutdown();
    return 0;
}
