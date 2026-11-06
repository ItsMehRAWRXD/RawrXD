// Executable acceptance: compatibility JS bridge must never claim QuickJS works.
#include "../../~dev/rawrxd/src/core/js_extension_host_production.cpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
int main() {
    using namespace RawrXD::JSExtension;
    RawrXD_JSExt_Shutdown();
    assert(!RawrXD_JSExt_IsInitialized());
    assert(!RawrXD_JSExt_Initialize());
    assert(!RawrXD_JSExt_IsInitialized());
    assert(!RawrXD_JSExt_ExecuteScript("1 + 1"));
    assert(!RawrXD_JSExt_ExecuteScript(nullptr));
    assert(!RawrXD_JSExt_LoadExtension("example.vsix"));
    assert(!RawrXD_JSExt_LoadExtension(nullptr));
    RawrXD_JSExt_Shutdown();
    assert(!RawrXD_JSExt_IsInitialized());
    JSExtensionHostHeadlessStubsStub();
}
