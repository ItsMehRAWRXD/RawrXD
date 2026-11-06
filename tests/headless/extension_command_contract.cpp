// Headless acceptance gates for the REAL production command registry.
// This includes the production translation unit, not a reimplemented mock.
// The bridge has no platform-specific dependencies; run with MSVC or g++.
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <thread>
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
    CHECK(!host.RegisterCommand("empty-handler", ExtensionHost::CommandHandler{}));
    CHECK(!host.RegisterExtensionCommand("extension", "empty-handler",
                                         ExtensionHost::CommandHandler{}));
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

    // Unload while a callback is already running: it must finish safely,
    // but no new dispatch may start after unregister returns.
    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
    std::atomic<int> completed{0};
    CHECK(host.RegisterExtensionCommand("extension-concurrent", "slow",
        [&](const auto&) {
            entered.store(true);
            while (!release.load()) std::this_thread::yield();
            ++completed;
            return true;
        }));
    std::thread worker([&] { host.ExecuteCommand("slow", ""); });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!entered.load() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    // Always release/join before reporting failure.
    const bool started = entered.load();
    host.UnregisterExtensionCommands("extension-concurrent");
    const bool denied = !host.ExecuteCommand("slow", "");
    release.store(true);
    worker.join();
    CHECK(started);
    CHECK(denied);
    CHECK(completed.load() == 1);

    CHECK(host.UnregisterCommand("throws"));
    CHECK(!host.UnregisterCommand("throws"));
    CHECK(host.GetAvailableCommands().empty());

    // Shutdown while a command is executing must not deadlock; a new
    // registry generation must not resurrect old extension commands.
    std::atomic<bool> shutdownEntered{false};
    std::atomic<bool> shutdownRelease{false};
    std::atomic<int> shutdownCompleted{0};
    CHECK(host.RegisterExtensionCommand("extension-shutdown", "shutdown-slow",
        [&](const auto&) {
            shutdownEntered.store(true);
            while (!shutdownRelease.load()) std::this_thread::yield();
            ++shutdownCompleted;
            return true;
        }));
    std::thread shutdownWorker([&] { host.ExecuteCommand("shutdown-slow", ""); });
    const auto shutdownDeadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!shutdownEntered.load() &&
           std::chrono::steady_clock::now() < shutdownDeadline)
        std::this_thread::yield();
    const bool shutdownStarted = shutdownEntered.load();
    host.Shutdown();
    const bool shutdownDenied = !host.ExecuteCommand("shutdown-slow", "");
    CHECK(host.Initialize());
    const bool restartDenied = !host.ExecuteCommand("shutdown-slow", "");
    shutdownRelease.store(true);
    shutdownWorker.join();
    CHECK(shutdownStarted);
    CHECK(shutdownDenied);
    CHECK(restartDenied);
    CHECK(shutdownCompleted.load() == 1);

    // Shutdown invalidates previously registered callbacks, not just visibility.
    int invocations = 0;
    CHECK(host.RegisterExtensionCommand("extension-lifecycle", "before-shutdown",
        [&](const auto&) { ++invocations; return true; }));
    CHECK(host.ExecuteCommand("before-shutdown", ""));
    CHECK(invocations == 1);
    host.Shutdown();
    CHECK(!host.IsInitialized());
    CHECK(!host.ExecuteCommand("before-shutdown", ""));
    CHECK(invocations == 1);
    CHECK(!host.ExecuteCommand("unknown", ""));
    CHECK(host.GetAvailableCommands().empty());
    CHECK(host.Initialize());
    CHECK(host.GetAvailableCommands().empty());
    host.Shutdown();
    std::cout << "PASS: production extension command registry contract\n";
    return EXIT_SUCCESS;
}
