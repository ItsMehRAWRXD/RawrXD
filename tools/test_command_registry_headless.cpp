// Compiles and executes the actual production CommandRegistry implementation.
// No dummy registry and no model inference. Only Win32 built-in UI handlers are excluded.
#define RAWRXD_COMMAND_REGISTRY_HEADLESS
#include "../~dev/rawrxd/src/core/command_registry.cpp"
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
int main() {
    auto& r = RawrXD::CommandRegistry::Instance();
    using RawrXD::Command;
    using RawrXD::CommandContext;
    int pass=0;
    auto test=[&](const char* name,bool ok){std::cout<<name<<"="<<(ok?"PASS":"FAIL")<<"\n";pass+=ok;};
    auto cmd=[](std::string id, RawrXD::CommandHandler handler) {
        Command c; c.id=std::move(id);c.title=c.id;c.handler=std::move(handler);return c;
    };
    test("01_missing_command",!r.ExecuteCommand("fixture.missing"));
    test("02_reject_empty_id",!r.RegisterCommand(cmd("",[](CommandContext&){})));
    test("03_reject_missing_handler",!r.RegisterCommand(cmd("fixture.nohandler",{})));
    int called=0;
    test("04_register",r.RegisterCommand(cmd("fixture.one",[&](CommandContext&){++called;})));
    test("05_duplicate_rejected",!r.RegisterCommand(cmd("fixture.one",[](CommandContext&){})));
    test("06_execute",r.ExecuteCommand("fixture.one")&&called==1);
    test("07_has_command",r.HasCommand("fixture.one"));
    test("08_nested_dispatch",r.RegisterCommand(cmd("fixture.nested",[&](CommandContext& c){if(!r.ExecuteCommand("fixture.one"))c.errorMessage="nested failed";}))&&r.ExecuteCommand("fixture.nested")&&called==2);
    test("09_context_mutation",r.RegisterCommand(cmd("fixture.context",[&](CommandContext&){r.SetContext("fixture.ready",true);}))&&r.ExecuteCommand("fixture.context")&&r.GetContext("fixture.ready"));
    auto conditioned=cmd("fixture.conditioned",[](CommandContext&){});conditioned.when={"fixture.enabled"};
    test("10_register_condition",r.RegisterCommand(conditioned));
    test("11_condition_denied",!r.ExecuteCommand("fixture.conditioned"));
    r.SetContext("fixture.enabled",true);
    test("12_condition_allowed",r.ExecuteCommand("fixture.conditioned"));
    test("13_exception_denied",r.RegisterCommand(cmd("fixture.throw",[](CommandContext&){throw std::runtime_error("fixture");}))&&!r.ExecuteCommand("fixture.throw"));
    test("14_error_denied",r.RegisterCommand(cmd("fixture.error",[](CommandContext& c){c.errorMessage="failure";}))&&!r.ExecuteCommand("fixture.error"));
    Command ext=cmd("fixture.ext",[&](CommandContext&){++called;});ext.keybinding="Ctrl+Alt+E";
    test("15_extension_register",r.RegisterExtensionCommand("fixture.publisher",ext));
    test("16_extension_duplicate",!r.RegisterExtensionCommand("fixture.other",ext));
    test("17_extension_keybinding",r.GetCommandForKeybinding("Ctrl+Alt+E")=="fixture.ext");
    test("18_extension_execute",r.ExecuteCommand("fixture.ext")&&called==3);
    r.UnregisterExtensionCommands("fixture.publisher");
    test("19_extension_unload",!r.HasCommand("fixture.ext"));
    test("20_extension_keybinding_cleanup",r.GetCommandForKeybinding("Ctrl+Alt+E").empty());
    test("21_extension_reinstall",r.RegisterExtensionCommand("fixture.publisher",ext));
    test("22_unregister",r.UnregisterCommand("fixture.one"));
    test("23_unregistered_denied",!r.ExecuteCommand("fixture.one"));
    std::atomic<int> concurrent{0};
    test("24_parallel_register",r.RegisterCommand(cmd("fixture.parallel",[&](CommandContext&){++concurrent;})));
    std::thread a([&]{for(int i=0;i<100;++i)r.ExecuteCommand("fixture.parallel");});
    std::thread b([&]{for(int i=0;i<100;++i)r.ExecuteCommand("fixture.parallel");});
    a.join();b.join();
    test("25_parallel_execution",concurrent==200);
    r.UnregisterExtensionCommands("fixture.publisher");
    std::cout<<"CENTRAL_REGISTRY="<<pass<<"/25\n";
    return pass==25?0:1;
}
