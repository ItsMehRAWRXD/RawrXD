// End-to-end headless fixture: real production extension bridge -> central IDE
// command registry -> callback -> extension unload. No inference required.
#define RAWRXD_COMMAND_REGISTRY_HEADLESS
#include "../~dev/rawrxd/src/core/command_registry.cpp"
#include "../~dev/rawrxd/src/core/extension_host_production.cpp"
#include <iostream>
#include <string>
int main() {
    using RawrXD::Command;
    using RawrXD::CommandContext;
    auto& registry=RawrXD::CommandRegistry::Instance();
    auto& bridge=RawrXD::Extensions::ExtensionHost::GetInstance();
    int passed=0;
    auto test=[&](const char* label,bool result){
        std::cout<<label<<"="<<(result?"PASS":"FAIL")<<"\n";
        if(result)++passed;
    };
    bridge.Shutdown();
    test("01_bridge_init",bridge.Initialize());
    int diskFixtureWrites=0;
    std::string lastPayload;
    test("02_bridge_register",bridge.RegisterCommand("fixture.edit",[&](const std::string& payload){
        ++diskFixtureWrites;lastPayload=payload;return payload=="replace:before:after";
    }));
    Command command;
    command.id="fixture.edit";command.title="Fixture Edit";command.category="Extension";
    command.keybinding="Ctrl+Alt+F";
    command.handler=[&](CommandContext& ctx){
        const std::string payload=ctx.arguments.empty()?"":ctx.arguments[0];
        if(!bridge.ExecuteCommand("fixture.edit",payload))
            ctx.errorMessage="Extension command rejected";
    };
    test("03_registry_register",registry.RegisterExtensionCommand("fixture.publisher",command));
    test("04_palette_visible",!registry.SearchCommands("Fixture Edit").empty());
    test("05_shortcut_route",registry.GetCommandForKeybinding("Ctrl+Alt+F")=="fixture.edit");
    CommandContext ctx;ctx.arguments={"replace:before:after"};
    test("06_dispatch_success",registry.ExecuteCommand("fixture.edit",ctx));
    test("07_callback_payload",diskFixtureWrites==1&&lastPayload=="replace:before:after");
    CommandContext rejected;rejected.arguments={"bad"};
    test("08_callback_rejection",!registry.ExecuteCommand("fixture.edit",rejected));
    test("09_error_propagated",!rejected.errorMessage.empty());
    test("10_duplicate_denied",!registry.RegisterExtensionCommand("fixture.attacker",command));
    test("11_bridge_unload",bridge.UnregisterCommand("fixture.edit"));
    CommandContext missing;missing.arguments={"replace:before:after"};
    test("12_bridge_unload_denies",!registry.ExecuteCommand("fixture.edit",missing));
    registry.UnregisterExtensionCommands("fixture.publisher");
    test("13_registry_unload",!registry.HasCommand("fixture.edit"));
    test("14_shortcut_removed",registry.GetCommandForKeybinding("Ctrl+Alt+F").empty());
    test("15_palette_removed",registry.SearchCommands("Fixture Edit").empty());
    bridge.Shutdown();
    std::cout<<"EXTENSION_CENTRAL_INTEGRATION="<<passed<<"/15\n";
    return passed==15?0:1;
}
