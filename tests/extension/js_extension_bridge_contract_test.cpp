// Contract test for the compatibility-only JS extension bridge.
// PASS means it correctly refuses unsupported operations, NOT that extensions work.
#include <cstdlib>
#include <iostream>
extern "C" {
bool RawrXD_JSExt_Initialize();
void RawrXD_JSExt_Shutdown();
bool RawrXD_JSExt_IsInitialized();
bool RawrXD_JSExt_ExecuteScript(const char*);
bool RawrXD_JSExt_LoadExtension(const char*);
}
static void check(bool condition, const char* message) {
    if (!condition) { std::cerr << "FAIL: " << message << "\n"; std::exit(1); }
}
int main() {
    RawrXD_JSExt_Shutdown();
    check(!RawrXD_JSExt_IsInitialized(), "initial state");
    check(!RawrXD_JSExt_Initialize(), "unsupported initialization");
    check(!RawrXD_JSExt_IsInitialized(), "no false initialized state");
    check(!RawrXD_JSExt_ExecuteScript(nullptr), "null script rejected");
    check(!RawrXD_JSExt_ExecuteScript("globalThis.fixture = 1"), "script not falsely executed");
    check(!RawrXD_JSExt_LoadExtension(nullptr), "null path rejected");
    check(!RawrXD_JSExt_LoadExtension("fixture-extension"), "extension not falsely loaded");
    RawrXD_JSExt_Shutdown();
    check(!RawrXD_JSExt_IsInitialized(), "shutdown state");
    std::cout << "PASS_FAIL_CLOSED: 8 checks; QuickJS/VSIX execution NOT certified\n";
}
