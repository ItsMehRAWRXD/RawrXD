// Model-free smoke test of the production compatibility bridge.
// This does not test QuickJS; it asserts that a bridge without an engine
// never advertises initialization, execution or extension installation.
#include <cassert>
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
    assert(!RawrXD_JSExt_IsInitialized());
    assert(!RawrXD_JSExt_Initialize());
    assert(!RawrXD_JSExt_IsInitialized());
    assert(!RawrXD_JSExt_ExecuteScript("1 + 1"));
    assert(!RawrXD_JSExt_ExecuteScript(nullptr));
    assert(!RawrXD_JSExt_LoadExtension("dummy.vsix"));
    assert(!RawrXD_JSExt_LoadExtension(nullptr));
    RawrXD_JSExt_Shutdown();
    assert(!RawrXD_JSExt_IsInitialized());
    std::cout << "PASS: bridge rejects unsupported runtime operations\n";
}
