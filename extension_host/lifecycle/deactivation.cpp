// deactivation.cpp — Extension Deactivation Lifecycle
#include "../extension_manager.hpp"

namespace RawrXD {
namespace ExtensionHost {

// ============================================================================
// Extension Deactivation Manager
// ============================================================================
class DeactivationManager {
public:
    static DeactivationManager& Get();

    bool DeactivateExtension(ExtensionInstance* instance);
    void DeactivateAll();
    void DeactivateByEvent(const std::string& event);

private:
    DeactivationManager() = default;
};

DeactivationManager& DeactivationManager::Get() {
    static DeactivationManager instance;
    return instance;
}

bool DeactivationManager::DeactivateExtension(ExtensionInstance* instance) {
    if (!instance) return false;
    if (instance->GetState() != ExtensionState::Active) return false;

    // Call extension's deactivate function
    std::filesystem::path deactivateJs = instance->GetManifest().installPath / "deactivate.js";
    if (std::filesystem::exists(deactivateJs)) {
        // TODO: Execute deactivation via QuickJS
    }

    // Unregister commands
    // TODO: Track registered commands per extension and unregister them

    // Clean up resources
    instance->Deactivate();
    return true;
}

void DeactivationManager::DeactivateAll() {
    // Called during shutdown
    // TODO: Iterate all active extensions and deactivate
}

void DeactivationManager::DeactivateByEvent(const std::string& event) {
    // Deactivate extensions that registered for this event
    // TODO: Implement event-based deactivation
}

} // namespace ExtensionHost
} // namespace RawrXD
