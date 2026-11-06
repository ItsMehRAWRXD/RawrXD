// Model-free smoke test of the production compatibility bridge.
// This does not test QuickJS; it asserts that a bridge without an engine
// never advertises initialization, execution or extension installation.
#include <cstdlib>
#include <iostream>

extern "C" {
bool RawrXD_JSExt_Initialize();
void RawrXD_JSExt_Shutdown();
bool RawrXD_JSExt_IsInitialized();
bool RawrXD_JSExt_ExecuteScript(const char*);
bool RawrXD_JSExt_LoadExtension(const char*);
}

int main() {
    RawrXD_JSExt_Shutdown();
    if (!(!RawrXD_JSExt_IsInitialized())) { std::cerr << "FAIL: !RawrXD_JSExt_IsInitialized()" << '\n'; return EXIT_FAILURE; }
    if (!(!RawrXD_JSExt_Initialize())) { std::cerr << "FAIL: !RawrXD_JSExt_Initialize()" << '\n'; return EXIT_FAILURE; }
    if (!(!RawrXD_JSExt_IsInitialized())) { std::cerr << "FAIL: !RawrXD_JSExt_IsInitialized()" << '\n'; return EXIT_FAILURE; }
    if (!(!RawrXD_JSExt_ExecuteScript("1 + 1"))) { std::cerr << "FAIL: !RawrXD_JSExt_ExecuteScript(\"1 + 1\")" << '\n'; return EXIT_FAILURE; }
    if (!(!RawrXD_JSExt_ExecuteScript(nullptr))) { std::cerr << "FAIL: !RawrXD_JSExt_ExecuteScript(nullptr)" << '\n'; return EXIT_FAILURE; }
    if (!(!RawrXD_JSExt_LoadExtension("dummy.vsix"))) { std::cerr << "FAIL: !RawrXD_JSExt_LoadExtension(\"dummy.vsix\")" << '\n'; return EXIT_FAILURE; }
    if (!(!RawrXD_JSExt_LoadExtension(nullptr))) { std::cerr << "FAIL: !RawrXD_JSExt_LoadExtension(nullptr)" << '\n'; return EXIT_FAILURE; }
    RawrXD_JSExt_Shutdown();
    if (!(!RawrXD_JSExt_IsInitialized())) { std::cerr << "FAIL: !RawrXD_JSExt_IsInitialized()" << '\n'; return EXIT_FAILURE; }
    std::cout << "PASS: bridge rejects unsupported runtime operations\n";
}
