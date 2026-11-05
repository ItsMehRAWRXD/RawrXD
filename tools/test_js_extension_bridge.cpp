// Production JS compatibility bridge is not a runtime; deny fake success.
#include "../~dev/rawrxd/src/core/js_extension_host_production.cpp"
#include <iostream>
int main() {
    int passed = 0;
    auto check = [&](const char* name, bool ok) {
        std::cout << name << "=" << (ok ? "PASS" : "FAIL") << "\n";
        if (ok) ++passed;
    };
    RawrXD_JSExt_Shutdown();
    check("01_initial_state", !RawrXD_JSExt_IsInitialized());
    check("02_initialize_denied", !RawrXD_JSExt_Initialize());
    check("03_still_not_initialized", !RawrXD_JSExt_IsInitialized());
    check("04_script_denied", !RawrXD_JSExt_ExecuteScript("1+1"));
    check("05_null_script_denied", !RawrXD_JSExt_ExecuteScript(nullptr));
    check("06_empty_script_denied", !RawrXD_JSExt_ExecuteScript(""));
    check("07_extension_denied", !RawrXD_JSExt_LoadExtension("fixture"));
    check("08_null_extension_denied", !RawrXD_JSExt_LoadExtension(nullptr));
    check("09_empty_extension_denied", !RawrXD_JSExt_LoadExtension(""));
    check("10_repeated_initialize_denied", !RawrXD_JSExt_Initialize());
    RawrXD_JSExt_Shutdown();
    check("11_shutdown_state", !RawrXD_JSExt_IsInitialized());
    check("12_post_shutdown_script_denied", !RawrXD_JSExt_ExecuteScript("x"));
    check("13_post_shutdown_extension_denied", !RawrXD_JSExt_LoadExtension("x"));
    RawrXD::JSExtension::JSExtensionHostHeadlessStubsStub();
    check("14_compatibility_stub_no_state", !RawrXD_JSExt_IsInitialized());
    check("15_final_initialize_denied", !RawrXD_JSExt_Initialize());
    std::cout << "JS_BRIDGE_FAIL_CLOSED=" << passed << "/15\n";
    return passed == 15 ? 0 : 1;
}
