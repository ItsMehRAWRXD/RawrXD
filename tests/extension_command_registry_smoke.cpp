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
    // Additional lifecycle and reentrancy gates; no model or GUI required.
    check(!host.RegisterExtensionCommand("", "bad", [](const std::string&) { return true; }), "16 empty owner rejected");
    check(!host.RegisterExtensionCommand("ext.bad", "", [](const std::string&) { return true; }), "17 empty extension command rejected");
    check(!host.RegisterExtensionCommand("ext.bad", "bad", {}), "18 empty extension callback rejected");
    check(host.RegisterCommand("host.run", [](const std::string&) { return true; }), "19 host command registered");
    host.UnregisterExtensionCommands("other.owner");
    check(host.ExecuteCommand("host.run", ""), "20 unrelated unload preserves host command");
    check(host.UnregisterCommand("host.run"), "21 explicit unregister succeeds");
    check(!host.UnregisterCommand("host.run"), "22 duplicate unregister fails");
    check(!host.ExecuteCommand("host.run", ""), "23 removed command fails closed");
    check(host.RegisterCommand("nested", [&](const std::string&) {
        return host.RegisterCommand("from.nested", [](const std::string&) { return true; });
    }), "24 reentrant command registered");
    check(host.ExecuteCommand("nested", ""), "25 callback can register command without deadlock");
    check(host.ExecuteCommand("from.nested", ""), "26 nested registration is executable");
    check(host.RegisterExtensionCommand("ext.beta", "beta.run", [](const std::string&) { return false; }), "27 false-returning extension registered");
    check(!host.ExecuteCommand("beta.run", ""), "28 callback false propagates");
    const auto available = host.GetAvailableCommands();
    check(std::find(available.begin(), available.end(), "beta.run") != available.end(), "29 available commands reflect registry");
    host.UnregisterExtensionCommands("ext.beta");
    check(!host.ExecuteCommand("beta.run", ""), "30 extension unload removes owned callback");
    host.Shutdown();
    check(!host.IsInitialized() && host.GetAvailableCommands().empty() && !host.ExecuteCommand("throws", ""), "15 shutdown clears registry");
    std::cout << "RESULT " << (checks - failures) << "/" << checks << " checks; " << (failures ? "FAIL" : "PASS") << '\n';
    return failures ? 1 : 0;
}
