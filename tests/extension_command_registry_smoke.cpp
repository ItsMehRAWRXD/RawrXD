// Standalone deterministic regression for the extension command registry.
// Build: c++ -std=c++17 -Wall -Wextra -pedantic tests/extension_command_registry_smoke.cpp -o extension_registry_smoke
// Run: ./extension_registry_smoke
// This exercises the actual production registry translation unit; it does NOT test
// QuickJS, VSIX, Windows UI, GPU inference, or installed extensions.
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "../~dev/rawrxd/src/core/extension_host_production.cpp"

int main() {
    using RawrXD::Extensions::ExtensionHost;
    auto& host = ExtensionHost::GetInstance();
    int failures = 0;
    int checks = 0;
    auto check = [&](bool condition, const char* name) {
        ++checks;
        std::cout << (condition ? "PASS " : "FAIL ") << name << '\n';
        if (!condition) ++failures;
    };
    host.Shutdown();
    check(!host.IsInitialized(), "01 starts uninitialized");
    check(!host.ExecuteCommand("missing", ""), "02 uninitialized execution rejected");
    check(!host.RegisterCommand("early", [](const std::string&) { return true; }), "03 pre-init registration rejected");
    check(host.Initialize(), "04 initialization");
    check(host.IsInitialized(), "05 initialized state");
    check(!host.RegisterCommand("", [](const std::string&) { return true; }), "06 empty command rejected");
    check(!host.RegisterCommand("empty-handler", {}), "07 null handler rejected");
    std::string received;
    check(host.RegisterExtensionCommand("ext.alpha", "alpha.run", [&](const std::string& args) { received = args; return true; }), "08 extension command registered");
    check(!host.RegisterExtensionCommand("ext.beta", "alpha.run", [](const std::string&) { return true; }), "09 duplicate rejected");
    check(host.ExecuteCommand("alpha.run", "payload") && received == "payload", "10 callback receives arguments");
    check(!host.ExecuteCommand("unknown", ""), "11 unknown command rejected");
    check(host.RegisterCommand("throws", [](const std::string&) -> bool { throw std::runtime_error("expected"); }), "12 throwing callback registered");
    check(!host.ExecuteCommand("throws", ""), "13 exception converted to failure");
    host.UnregisterExtensionCommands("ext.alpha");
    check(!host.ExecuteCommand("alpha.run", ""), "14 owner unload removes command");
    host.Shutdown();
    check(!host.IsInitialized() && host.GetAvailableCommands().empty() && !host.ExecuteCommand("throws", ""), "15 shutdown clears registry");
    std::cout << "RESULT " << (checks - failures) << "/" << checks << " checks; " << (failures ? "FAIL" : "PASS") << '\n';
    return failures ? 1 : 0;
}
