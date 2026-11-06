// Standalone runtime contract test of the C ABI compatibility bridge.
// Compile and link against js_extension_host_production.cpp (not the QuickJS host).
// Passing here proves fail-closed bridge behavior, NOT extension execution.
#include <iostream>
extern "C" bool RawrXD_JSExt_Initialize();
extern "C" void RawrXD_JSExt_Shutdown();
extern "C" bool RawrXD_JSExt_IsInitialized();
extern "C" bool RawrXD_JSExt_ExecuteScript(const char*);
extern "C" bool RawrXD_JSExt_LoadExtension(const char*);
int main() {
    int failures = 0;
    auto check = [&](bool ok, const char* label) {
        std::cout << (ok ? "PASS " : "FAIL ") << label << '\n';
        if (!ok) ++failures;
    };
    check(!RawrXD_JSExt_IsInitialized(), "initially uninitialized");
    check(!RawrXD_JSExt_Initialize(), "initialize fails closed");
    check(!RawrXD_JSExt_IsInitialized(), "initialize does not claim ready");
    check(!RawrXD_JSExt_ExecuteScript("1+1"), "script fails closed");
    check(!RawrXD_JSExt_LoadExtension("fixture"), "load fails closed");
    RawrXD_JSExt_Shutdown();
    check(!RawrXD_JSExt_IsInitialized(), "shutdown leaves uninitialized");
    std::cout << "RESULT " << (failures ? "FAIL" : "PASS")
              << " failures=" << failures << '\n';
    return failures ? 1 : 0;
}
