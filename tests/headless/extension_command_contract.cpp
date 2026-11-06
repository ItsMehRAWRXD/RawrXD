// Headless acceptance gates for the REAL production command registry.
// This includes the production translation unit, not a reimplemented mock.
// The bridge has no platform-specific dependencies; run with MSVC or g++.
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include "../../~dev/rawrxd/src/core/extension_host_production.cpp"

// CHECK always evaluates the expression, including Release/NDEBUG builds.
#define CHECK(expr) do { \
    if (!(expr)) { \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << " " << #expr << "\n"; \
        return EXIT_FAILURE; \
    } \
} while (false)

int main() {
    using RawrXD::Extensions::ExtensionHost;
    auto& host = ExtensionHost::GetInstance();

    host.Shutdown();
    CHECK(!host.IsInitialized());
    CHECK(!host.RegisterCommand("before-init", [](const auto&) { return true; }));

    CHECK(host.Initialize());
    CHECK(!host.RegisterCommand("", [](const auto&) { return true; }));
    CHECK(!host.RegisterExtensionCommand("", "x", [](const auto&) { return true; }));
    CHECK(!host.RegisterExtensionCommand("extension", "", [](const auto&) { return true; }));
    CHECK(host.RegisterExtensionCommand("extension-a", "echo",
        [](const std::string& arg) { return arg == "expected"; }));
    CHECK(!host.RegisterExtensionCommand("extension-b", "echo",
        [](const auto&) { return true; }));
    CHECK(host.ExecuteCommand("echo", "expected"));
    CHECK(!host.ExecuteCommand("echo", "wrong"));

    // Reentrant dispatch detects callbacks executed while the registry mutex is held.
    CHECK(host.RegisterExtensionCommand("extension-a", "nested",
        [&](const auto&) { return host.ExecuteCommand("echo", "expected"); }));
    CHECK(host.ExecuteCommand("nested", ""));

    CHECK(host.RegisterCommand("throws",
        [](const auto&) -> bool { throw std::runtime_error("callback failed"); }));
    CHECK(!host.ExecuteCommand("throws", ""));
    CHECK(!host.ExecuteCommand("unknown", ""));
    CHECK(host.GetAvailableCommands().size() == 3);

    host.UnregisterExtensionCommands("extension-b");
    CHECK(host.ExecuteCommand("echo", "expected"));
    host.UnregisterExtensionCommands("extension-a");
    CHECK(!host.ExecuteCommand("echo", "expected"));
    CHECK(!host.ExecuteCommand("nested", ""));
    CHECK(host.GetAvailableCommands().size() == 1);

    // A command may unregister itself; execution must not hold the registry lock.
    CHECK(host.RegisterExtensionCommand("extension-self", "self-remove",
        [&](const auto&) {
            host.UnregisterExtensionCommands("extension-self");
            return true;
        }));
    CHECK(host.ExecuteCommand("self-remove", ""));
    CHECK(!host.ExecuteCommand("self-remove", ""));

    // A callback can register a command without deadlocking the host.
    CHECK(host.RegisterCommand("register-during-callback",
        [&](const auto&) {
            return host.RegisterCommand("newly-registered",
                [](const auto&) { return true; });
        }));
    CHECK(host.ExecuteCommand("register-during-callback", ""));
    CHECK(host.ExecuteCommand("newly-registered", ""));
    CHECK(host.UnregisterCommand("register-during-callback"));
    CHECK(host.UnregisterCommand("newly-registered"));

    CHECK(host.UnregisterCommand("throws"));
    CHECK(!host.UnregisterCommand("throws"));
    CHECK(host.GetAvailableCommands().empty());

    host.Shutdown();
    CHECK(!host.IsInitialized());
    CHECK(!host.ExecuteCommand("unknown", ""));
    CHECK(host.GetAvailableCommands().empty());
    CHECK(host.Initialize());
    CHECK(host.GetAvailableCommands().empty());
    host.Shutdown();
    std::cout << "PASS: production extension command registry contract\n";
    return EXIT_SUCCESS;
}
