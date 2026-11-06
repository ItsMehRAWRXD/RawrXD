// js_extension_host_production.cpp — compatibility-only C ABI bridge
// This translation unit does NOT implement a JavaScript runtime or VSIX loader.
// Unsupported operations deliberately fail closed; use js_extension_host.cpp
// for the real QuickJS-backed host. Do not treat a successful link as activation.

#include <mutex>
#include <string>

namespace RawrXD {
namespace JSExtension {

class JSExtensionHost {
public:
    static JSExtensionHost& Instance() {
        static JSExtensionHost instance;
        return instance;
    }

    // This bridge has no JavaScript engine or module loader.
    // The full QuickJS host is implemented separately in js_extension_host.cpp.
    // Do not claim runtime initialization, script execution, or installation.
    bool Initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        return false;
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        initialized_ = false;
    }

    bool IsInitialized() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return initialized_;
    }

    bool ExecuteScript(const char* script) {
        (void)script;
        return false;
    }

    bool LoadExtension(const char* path) {
        (void)path;
        return false;
    }

private:
    JSExtensionHost() = default;
    ~JSExtensionHost() {
        Shutdown();
    }
    
    mutable std::mutex mutex_;
    bool initialized_ = false;
};

#ifdef _WIN32
#define RAWRXD_BRIDGE_API __declspec(dllexport)
#else
#define RAWRXD_BRIDGE_API __attribute__((visibility("default")))
#endif

extern "C" {

RAWRXD_BRIDGE_API bool RawrXD_JSExt_Initialize() {
    return JSExtensionHost::Instance().Initialize();
}

RAWRXD_BRIDGE_API void RawrXD_JSExt_Shutdown() {
    JSExtensionHost::Instance().Shutdown();
}

RAWRXD_BRIDGE_API bool RawrXD_JSExt_IsInitialized() {
    return JSExtensionHost::Instance().IsInitialized();
}

RAWRXD_BRIDGE_API bool RawrXD_JSExt_ExecuteScript(const char* script) {
    return JSExtensionHost::Instance().ExecuteScript(script);
}

RAWRXD_BRIDGE_API bool RawrXD_JSExt_LoadExtension(const char* path) {
    return JSExtensionHost::Instance().LoadExtension(path);
}

void JSExtensionHostHeadlessStubsStub() {
    // Kept for binary compatibility
}

} // extern "C"

} // namespace JSExtension
} // namespace RawrXD
