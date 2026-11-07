// Portable regression tests for the production extension command registry.
// This is NOT a QuickJS/VSIX runtime certification.
#include "../src/core/extension_host_production.cpp"
#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>
#include <iostream>

static int failures = 0;
static void check(bool ok, const char* name) {
    if (!ok) { std::cerr << "FAIL " << name << '\n'; ++failures; }
    else std::cout << "PASS " << name << '\n';
}

int main() {
    using RawrXD::Extensions::ExtensionHost;
    auto& host = ExtensionHost::GetInstance();
    host.Shutdown();
    check(!host.ExecuteCommand("missing", ""), "fail closed before init");
    check(!host.RegisterCommand("early", [](const std::string&) { return true; }), "no registration before init");
    check(host.Initialize() && host.IsInitialized(), "initialize");
    check(!host.RegisterCommand("", [](const std::string&) { return true; }), "empty command rejected");
    check(!host.RegisterCommand("bad\nname", [](const std::string&) { return true; }), "control character rejected");
    check(!host.RegisterCommand(std::string(257, 'x'), [](const std::string&) { return true; }), "oversized command rejected");
    check(!host.RegisterCommand("null", {}), "null callback rejected");
    check(!host.RegisterExtensionCommand("", "invalid", [](const std::string&) { return true; }), "empty owner rejected");
    check(!host.RegisterExtensionCommand("bad owner", "invalid", [](const std::string&) { return true; }), "whitespace owner rejected");
    int called = 0;
    check(host.RegisterExtensionCommand("alpha", "alpha.run", [&](const std::string& arg) { ++called; return arg == "ok"; }), "register owned command");
    check(!host.RegisterExtensionCommand("beta", "alpha.run", [](const std::string&) { return true; }), "duplicate rejected");
    check(host.ExecuteCommand("alpha.run", "ok") && called == 1, "execute owned command");
    check(!host.ExecuteCommand("alpha.run", "bad") && called == 2, "callback false propagated");
    check(!host.ExecuteCommand("unknown", ""), "unknown command rejected");
    check(host.RegisterCommand("throws", [](const std::string&) -> bool { throw std::runtime_error("expected"); }), "register throwing callback");
    check(!host.ExecuteCommand("throws", ""), "callback exception isolated");
    check(host.RegisterExtensionCommand("beta", "beta.run", [](const std::string&) { return true; }), "register second owner");
    host.UnregisterExtensionCommands("alpha");
    check(!host.ExecuteCommand("alpha.run", ""), "owner unload removes commands");
    check(host.ExecuteCommand("beta.run", ""), "owner unload preserves other owners");
    check(host.RegisterCommand("nested", [&](const std::string&) { return host.UnregisterCommand("nested"); }), "register reentrant callback");
    check(host.ExecuteCommand("nested", ""), "callback reentrancy no deadlock");
    const auto names = host.GetAvailableCommands();
    check(std::find(names.begin(), names.end(), "alpha.run") == names.end(), "enumeration excludes removed commands");
    host.Shutdown();
    check(!host.IsInitialized() && host.GetAvailableCommands().empty(), "shutdown clears registry");
    check(!host.ExecuteCommand("beta.run", ""), "shutdown denies execution");
    check(host.Initialize() && !host.ExecuteCommand("beta.run", ""), "restart does not resurrect commands");
    host.Shutdown();
    std::cout << "RESULT " << (failures ? "FAIL" : "PASS") << " failures=" << failures << '\n';
    return failures ? 1 : 0;
}
