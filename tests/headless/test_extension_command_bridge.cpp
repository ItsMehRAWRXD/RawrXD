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
 std::cout << "RESULT " << passed << " passed " << failed << " failed\n";
 return failed ? 1 : 0;
}
