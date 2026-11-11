// ExtensionHost.cpp — Extension Host (Batch 5 X04)
#include "ExtensionHost.h"
#include <windows.h>

struct ExtensionHost::Impl {
    bool running = false;
};

ExtensionHost::ExtensionHost() : impl_(std::make_unique<Impl>()) {}
ExtensionHost::~ExtensionHost() { Stop(); }

bool ExtensionHost::Start() {
    impl_->running = true;
    return true;
}

void ExtensionHost::Stop() {
    impl_->running = false;
}

bool ExtensionHost::LoadExtension(const std::string& /*extensionPath*/) {
    return impl_->running;
}

void ExtensionHost::UnloadExtension(const std::string& /*extensionId*/) {
    // Stub
}
