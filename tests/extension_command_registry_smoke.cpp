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
    check(!host.RegisterExtensionCommand("", "bad", [](const std::string&) { return true; }), "15 empty owner rejected");
    check(!host.RegisterExtensionCommand("ext.bad", "", [](const std::string&) { return true; }), "16 empty extension command rejected");
    check(!host.RegisterExtensionCommand("ext.bad", "bad", {}), "17 empty extension callback rejected");
    check(host.RegisterCommand("host.run", [](const std::string&) { return true; }), "18 host command registered");
    host.UnregisterExtensionCommands("other.owner");
    check(host.ExecuteCommand("host.run", ""), "19 unrelated unload preserves host command");
    check(host.UnregisterCommand("host.run"), "20 explicit unregister succeeds");
    check(!host.UnregisterCommand("host.run"), "21 duplicate unregister fails");
    check(!host.ExecuteCommand("host.run", ""), "22 removed command fails closed");
    check(host.RegisterCommand("nested", [&](const std::string&) {
        return host.RegisterCommand("from.nested", [](const std::string&) { return true; });
    }), "23 reentrant command registered");
    check(host.ExecuteCommand("nested", ""), "24 callback can register command without deadlock");
    check(host.ExecuteCommand("from.nested", ""), "25 nested registration is executable");
    check(host.RegisterExtensionCommand("ext.beta", "beta.run", [](const std::string&) { return false; }), "26 false-returning extension registered");
    check(!host.ExecuteCommand("beta.run", ""), "27 callback false propagates");
    const auto available = host.GetAvailableCommands();
    check(std::find(available.begin(), available.end(), "beta.run") != available.end(), "28 available commands reflect registry");
    host.UnregisterExtensionCommands("ext.beta");
    check(!host.ExecuteCommand("beta.run", ""), "29 extension unload removes owned callback");
    // Batch 2: 15 additional deterministic lifecycle and isolation gates.
    check(host.RegisterExtensionCommand("ext.gamma", "gamma.run", [](const std::string&) { return true; }), "30 second owner registration");
    check(host.RegisterExtensionCommand("ext.delta", "delta.run", [](const std::string&) { return true; }), "31 independent owner registration");
    host.UnregisterExtensionCommands("ext.gamma");
    check(!host.ExecuteCommand("gamma.run", ""), "32 gamma unloaded");
    check(host.ExecuteCommand("delta.run", ""), "33 delta unaffected by gamma unload");
    check(host.UnregisterCommand("delta.run"), "34 direct removal of owned command");
    check(!host.ExecuteCommand("delta.run", ""), "35 direct removal blocks execution");
    host.UnregisterExtensionCommands("ext.delta");
    check(host.RegisterExtensionCommand("ext.delta", "delta.run", [](const std::string&) { return true; }), "36 owner can re-register after unload");
    check(host.ExecuteCommand("delta.run", ""), "37 re-registered callback executes");
    check(host.RegisterCommand("self.remove", [&](const std::string&) {
        return host.UnregisterCommand("self.remove");
    }), "38 self-removing callback registered");
    check(host.ExecuteCommand("self.remove", ""), "39 callback can unregister itself");
    check(!host.ExecuteCommand("self.remove", ""), "40 self-removal prevents future execution");
    check(!host.RegisterCommand("delta.run", [](const std::string&) { return true; }), "41 host cannot replace extension command");
    check(host.ExecuteCommand("delta.run", ""), "42 duplicate attempt preserved original callback");
    host.UnregisterExtensionCommands("ext.delta");
    check(host.RegisterCommand("delta.run", [](const std::string&) { return true; }), "43 command name reusable after unload");
    check(host.ExecuteCommand("delta.run", ""), "44 reused command executes");
    // Batch 3: 15 more gates, including the repeated-initialization defect.
    check(!host.Initialize(), "45 repeated initialize fails closed");
    check(host.IsInitialized(), "46 rejected initialize preserves running host");
    check(host.ExecuteCommand("delta.run", ""), "47 rejected initialize preserves callbacks");
    check(host.RegisterExtensionCommand("ext.epsilon", "epsilon.run", [](const std::string&) { return true; }), "48 epsilon registration");
    check(host.RegisterExtensionCommand("ext.zeta", "zeta.run", [](const std::string&) { return true; }), "49 zeta registration");
    host.UnregisterExtensionCommands("ext.epsilon");
    check(!host.ExecuteCommand("epsilon.run", ""), "50 epsilon unload");
    check(host.ExecuteCommand("zeta.run", ""), "51 zeta isolated");
    check(!host.UnregisterCommand("missing.command"), "52 unknown removal fails");
    check(!host.RegisterExtensionCommand("ext.zeta", "zeta.run", [](const std::string&) { return true; }), "53 duplicate owner command rejected");
    check(host.ExecuteCommand("zeta.run", ""), "54 original owner command preserved");
    host.Shutdown();
    check(!host.IsInitialized(), "55 shutdown state");
    check(!host.ExecuteCommand("zeta.run", ""), "56 shutdown rejects dispatch");
    check(host.Initialize(), "57 clean restart succeeds");
    check(host.GetAvailableCommands().empty(), "58 restart has no stale commands");
    check(host.RegisterCommand("after.restart", [](const std::string&) { return true; })
          && host.ExecuteCommand("after.restart", ""), "59 restart accepts new commands");
    host.Shutdown();
    check(!host.IsInitialized() && host.GetAvailableCommands().empty() && !host.ExecuteCommand("throws", ""), "60 shutdown clears registry");
    std::cout << "RESULT " << (checks - failures) << "/" << checks << " checks; " << (failures ? "FAIL" : "PASS") << '\n';
    return failures ? 1 : 0;
}
