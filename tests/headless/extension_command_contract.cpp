// Headless acceptance gates for the REAL production command registry.
// This includes the production translation unit, not a reimplemented mock.
// The bridge has no platform-specific dependencies; run with MSVC or g++.
#include <cassert>
#include <stdexcept>
#include <string>
#include "../../~dev/rawrxd/src/core/extension_host_production.cpp"

int main() {
    using RawrXD::Extensions::ExtensionHost;
    auto& host = ExtensionHost::GetInstance();

    host.Shutdown();
    assert(!host.IsInitialized());
    assert(!host.RegisterCommand("before-init", [](const auto&) { return true; }));

    assert(host.Initialize());
    assert(!host.RegisterCommand("", [](const auto&) { return true; }));
    assert(!host.RegisterExtensionCommand("", "x", [](const auto&) { return true; }));
    assert(!host.RegisterExtensionCommand("extension", "", [](const auto&) { return true; }));
    assert(host.RegisterExtensionCommand("extension-a", "echo",
        [](const std::string& arg) { return arg == "expected"; }));
    assert(!host.RegisterExtensionCommand("extension-b", "echo",
        [](const auto&) { return true; }));
    assert(host.ExecuteCommand("echo", "expected"));
    assert(!host.ExecuteCommand("echo", "wrong"));

    // Reentrant dispatch detects callbacks executed while the registry mutex is held.
    assert(host.RegisterExtensionCommand("extension-a", "nested",
        [&](const auto&) { return host.ExecuteCommand("echo", "expected"); }));
    assert(host.ExecuteCommand("nested", ""));

    assert(host.RegisterCommand("throws",
        [](const auto&) -> bool { throw std::runtime_error("callback failed"); }));
    assert(!host.ExecuteCommand("throws", ""));
    assert(!host.ExecuteCommand("unknown", ""));
    assert(host.GetAvailableCommands().size() == 3);

    host.UnregisterExtensionCommands("extension-b");
    assert(host.ExecuteCommand("echo", "expected"));
    host.UnregisterExtensionCommands("extension-a");
    assert(!host.ExecuteCommand("echo", "expected"));
    assert(!host.ExecuteCommand("nested", ""));
    assert(host.GetAvailableCommands().size() == 1);

    assert(host.UnregisterCommand("throws"));
    assert(!host.UnregisterCommand("throws"));
    assert(host.GetAvailableCommands().empty());

    host.Shutdown();
    assert(!host.IsInitialized());
    assert(!host.ExecuteCommand("unknown", ""));
    assert(host.GetAvailableCommands().empty());
    assert(host.Initialize());
    assert(host.GetAvailableCommands().empty());
    host.Shutdown();
    return 0;
}
