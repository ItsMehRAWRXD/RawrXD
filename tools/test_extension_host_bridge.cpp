// Standalone native acceptance for the production extension bridge.
// Includes the actual implementation so the tests cannot silently exercise a mock.
#include "../~dev/rawrxd/src/core/extension_host_production.cpp"
#include <iostream>
#include <thread>
#include <atomic>
int main() {
    auto& host = RawrXD::Extensions::ExtensionHost::GetInstance();
    int passed = 0;
    const auto check = [&](const char* label, bool ok) {
        std::cout << label << "=" << (ok ? "PASS" : "FAIL") << "\\n";
        if (ok) ++passed;
    };
    host.Shutdown();
    check("initial_uninitialized", !host.IsInitialized());
    check("uninitialized_command_denied", !host.ExecuteCommand("test", ""));
    check("uninitialized_commands_empty", host.GetAvailableCommands().empty());
    check("initialize", host.Initialize());
    check("initialized", host.IsInitialized());
    check("repeat_initialize", host.Initialize());
    check("unknown_command_denied", !host.ExecuteCommand("unknown", ""));
    check("empty_command_denied", !host.ExecuteCommand("", ""));
    check("argument_command_denied", !host.ExecuteCommand("unknown", "payload"));
    check("commands_not_fabricated", host.GetAvailableCommands().empty());
    std::atomic<int> falseReturns{0};
    std::thread a([&] { if (!host.ExecuteCommand("concurrent_a", "")) ++falseReturns; });
    std::thread b([&] { if (!host.ExecuteCommand("concurrent_b", "")) ++falseReturns; });
    a.join(); b.join();
    check("concurrent_commands_denied", falseReturns == 2);
    host.Shutdown();
    check("shutdown_uninitialized", !host.IsInitialized());
    check("post_shutdown_command_denied", !host.ExecuteCommand("test", ""));
    check("reinitialize", host.Initialize());
    host.Shutdown();
    check("final_shutdown", !host.IsInitialized());
    std::cout << "EXTENSION_BRIDGE=" << passed << "/15\\n";
    return passed == 15 ? 0 : 1;
}
