// Portable acceptance smoke: compile the ACTUAL production translation unit.
// No model, Ollama, GPU, or Windows GUI required.
#include "../../~dev/rawrxd/src/core/extension_host_production.cpp"
#include <iostream>
#include <stdexcept>
using RawrXD::Extensions::ExtensionHost;
static int failed=0, passed=0;
#define CHECK(label, expr) do { bool ok = (expr); std::cout << (ok ? "PASS " : "FAIL ") << label << '\n'; if(ok) ++passed; else ++failed; } while(0)
int main(){
 auto& h=ExtensionHost::GetInstance();
 h.Shutdown();
 CHECK("01 preinit execution denied", !h.ExecuteCommand("x", ""));
 CHECK("02 preinit registration denied", !h.RegisterCommand("x", [](auto const&){return true;}));
 CHECK("03 initialize", h.Initialize());
 CHECK("04 initialized flag", h.IsInitialized());
 CHECK("05 empty name rejected", !h.RegisterCommand("", [](auto const&){return true;}));
 CHECK("06 empty callback rejected", !h.RegisterCommand("x", {}));
 CHECK("07 register host command", h.RegisterCommand("x", [](auto const& a){return a=="ok";}));
 CHECK("08 duplicate command denied", !h.RegisterCommand("x", [](auto const&){return true;}));
 CHECK("09 handler arguments", h.ExecuteCommand("x", "ok") && !h.ExecuteCommand("x", "bad"));
 CHECK("10 unknown command denied", !h.ExecuteCommand("unknown", ""));
 CHECK("11 throwing callback contained", h.RegisterCommand("throw", [](auto const&)->bool{throw std::runtime_error("boom");}) && !h.ExecuteCommand("throw", ""));
 CHECK("12 extension-owned registration", h.RegisterExtensionCommand("publisher.ext", "ext.cmd", [](auto const&){return true;}));
 CHECK("13 extension owner cleanup", (h.UnregisterExtensionCommands("publisher.ext"), !h.ExecuteCommand("ext.cmd", "")));
 CHECK("14 unregister host command", h.UnregisterCommand("x") && !h.ExecuteCommand("x", ""));
 CHECK("15 malformed owner rejected", !h.RegisterExtensionCommand("bad owner", "bad.cmd", [](auto const&){return true;}));
 CHECK("16 shutdown clears state", (h.Shutdown(), !h.IsInitialized() && h.GetAvailableCommands().empty() && !h.ExecuteCommand("throw", "")));
 CHECK("17 idempotent initialize", h.Initialize() && h.Initialize());
 CHECK("18 missing unregister denied", !h.UnregisterCommand("not.registered"));
 CHECK("19 empty extension owner denied", !h.RegisterExtensionCommand("", "invalid.owner", [](auto const&){return true;}));
 CHECK("20 empty extension command denied", !h.RegisterExtensionCommand("owner", "", [](auto const&){return true;}));
 CHECK("21 null extension callback denied", !h.RegisterExtensionCommand("owner", "invalid.callback", {}));
 CHECK("22 tab owner denied", !h.RegisterExtensionCommand("bad\\towner", "invalid.tab", [](auto const&){return true;}));
 CHECK("23 register independent owners", h.RegisterExtensionCommand("one", "one.cmd", [](auto const&){return true;}) && h.RegisterExtensionCommand("two", "two.cmd", [](auto const&){return true;}));
 CHECK("24 owner cleanup isolated", (h.UnregisterExtensionCommands("one"), !h.ExecuteCommand("one.cmd", "") && h.ExecuteCommand("two.cmd", "")));
 CHECK("25 nested command dispatch", h.RegisterCommand("nested", [&](auto const&){return h.ExecuteCommand("two.cmd", "");}) && h.ExecuteCommand("nested", ""));
 CHECK("26 self-unregister callback", h.RegisterCommand("self.remove", [&](auto const&){return h.UnregisterCommand("self.remove");}) && h.ExecuteCommand("self.remove", "") && !h.ExecuteCommand("self.remove", ""));
 CHECK("27 callback can register command", h.RegisterCommand("register.inside", [&](auto const&){return h.RegisterCommand("registered.inside", [](auto const&){return true;});}) && h.ExecuteCommand("register.inside", "") && h.ExecuteCommand("registered.inside", ""));
 CHECK("28 shutdown clears owners", (h.Shutdown(), h.Initialize(), h.RegisterExtensionCommand("two", "two.cmd", [](auto const&){return true;})));
 CHECK("29 enumeration sorted", h.RegisterCommand("alpha", [](auto const&){return true;}) && h.GetAvailableCommands().front()=="alpha");
 CHECK("30 final shutdown", (h.Shutdown(), !h.IsInitialized() && h.GetAvailableCommands().empty()));
 h.Initialize();
 CHECK("31 reject newline command", !h.RegisterCommand("bad\\ncmd", [](auto const&){return true;}));
 CHECK("32 reject NUL command", !h.RegisterCommand(std::string("bad\\0cmd",7), [](auto const&){return true;}));
 CHECK("33 reject oversized command", !h.RegisterCommand(std::string(257, 'x'), [](auto const&){return true;}));
 CHECK("34 accept 256-character command", h.RegisterCommand(std::string(256, 'x'), [](auto const&){return true;}));
 CHECK("35 reject extension control character", !h.RegisterExtensionCommand("ext", "bad\\tcmd", [](auto const&){return true;}));
 CHECK("36 reject extension oversized command", !h.RegisterExtensionCommand("ext", std::string(257, 'x'), [](auto const&){return true;}));
 CHECK("37 reject DEL command", !h.RegisterCommand(std::string("bad")+char(127), [](auto const&){return true;}));
 CHECK("38 preserve UTF8 command bytes", h.RegisterCommand("ext.\\xC3\\xA9", [](auto const&){return true;}) && h.ExecuteCommand("ext.\\xC3\\xA9", ""));
 CHECK("39 cleanup after validation tests", (h.Shutdown(), h.GetAvailableCommands().empty()));
 std::cout << "RESULT " << passed << " passed " << failed << " failed\n";
 return failed ? 1 : 0;
}
