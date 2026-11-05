// Real production bridge acceptance; no mocked registry or model inference.
#include "../~dev/rawrxd/src/core/extension_host_production.cpp"
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
int main() {
    auto& host = RawrXD::Extensions::ExtensionHost::GetInstance();
    int passed = 0;
    const auto check = [&](const char* name, bool ok) {
        std::cout << name << "=" << (ok ? "PASS" : "FAIL") << "\n";
        if (ok) ++passed;
    };
    host.Shutdown();
    check("01_initially_stopped", !host.IsInitialized());
    check("02_uninitialized_denies", !host.ExecuteCommand("demo", ""));
    check("03_register_before_init_denied", !host.RegisterCommand("demo", [](const std::string&) { return true; }));
    check("04_initialize", host.Initialize());
    check("05_initialized", host.IsInitialized());
    check("06_empty_name_denied", !host.RegisterCommand("", [](const std::string&) { return true; }));
    check("07_empty_handler_denied", !host.RegisterCommand("empty", {}));
    std::string received;
    check("08_register", host.RegisterCommand("demo", [&](const std::string& a) { received = a; return true; }));
    check("09_duplicate_denied", !host.RegisterCommand("demo", [](const std::string&) { return true; }));
    check("10_list_registered", host.GetAvailableCommands().size() == 1 && host.GetAvailableCommands()[0] == "demo");
    check("11_execute_real_callback", host.ExecuteCommand("demo", "fixture") && received == "fixture");
    check("12_unknown_denied", !host.ExecuteCommand("missing", ""));
    check("13_throw_is_failure", host.RegisterCommand("throw", [](const std::string&) -> bool { throw std::runtime_error("fixture"); }) && !host.ExecuteCommand("throw", ""));
    check("14_false_result_preserved", host.RegisterCommand("fail", [](const std::string&) { return false; }) && !host.ExecuteCommand("fail", ""));
    check("15_nested_dispatch", host.RegisterCommand("nested", [&](const std::string& a) { return host.ExecuteCommand("demo", a); }) && host.ExecuteCommand("nested", "nested-arg") && received == "nested-arg");
    check("16_self_unregister", host.RegisterCommand("once", [&](const std::string&) { return host.UnregisterCommand("once"); }) && host.ExecuteCommand("once", "") && !host.ExecuteCommand("once", ""));
    check("17_unregister", host.UnregisterCommand("demo") && !host.ExecuteCommand("demo", ""));
    check("18_unregister_missing", !host.UnregisterCommand("missing"));
    std::atomic<int> calls{0};
    check("19_register_concurrent", host.RegisterCommand("parallel", [&](const std::string&) { ++calls; return true; }));
    std::thread t1([&] { for (int i=0; i<100; ++i) host.ExecuteCommand("parallel", ""); });
    std::thread t2([&] { for (int i=0; i<100; ++i) host.ExecuteCommand("parallel", ""); });
    t1.join(); t2.join();
    check("20_concurrent_dispatch", calls == 200);
    check("26_owner_register_a", host.RegisterExtensionCommand("owner.a", "owner.a.cmd", [](const std::string&){ return true; }));
    check("27_owner_register_b", host.RegisterExtensionCommand("owner.b", "owner.b.cmd", [](const std::string&){ return true; }));
    check("28_owner_empty_denied", !host.RegisterExtensionCommand("", "owner.bad", [](const std::string&){ return true; }));
    check("29_owner_duplicate_denied", !host.RegisterExtensionCommand("owner.b", "owner.a.cmd", [](const std::string&){ return true; }));
    check("30_owner_execute_a", host.ExecuteCommand("owner.a.cmd", ""));
    check("31_owner_execute_b", host.ExecuteCommand("owner.b.cmd", ""));
    host.UnregisterExtensionCommands("owner.a");
    check("32_owner_a_unloaded", !host.ExecuteCommand("owner.a.cmd", ""));
    check("33_owner_b_survives", host.ExecuteCommand("owner.b.cmd", ""));
    check("34_host_command_survives", host.ExecuteCommand("parallel", ""));
    check("35_owner_b_direct_unregister", host.UnregisterCommand("owner.b.cmd"));
    host.UnregisterExtensionCommands("owner.b");
    check("36_owner_b_unload_idempotent", !host.ExecuteCommand("owner.b.cmd", ""));
    check("37_owner_reinstall", host.RegisterExtensionCommand("owner.a", "owner.a.cmd", [](const std::string&){ return true; }));
    host.Shutdown();
    check("21_shutdown", !host.IsInitialized() && host.GetAvailableCommands().empty());
    check("22_after_shutdown_denied", !host.ExecuteCommand("parallel", ""));
    check("23_unregister_after_shutdown_denied", !host.UnregisterCommand("parallel"));
    check("24_reinitialize", host.Initialize());
    check("25_old_commands_cleared", host.GetAvailableCommands().empty() && !host.ExecuteCommand("parallel", ""));
    host.Shutdown();
    std::cout << "EXTENSION_BRIDGE=" << passed << "/37\n";
    return passed == 37 ? 0 : 1;
}
