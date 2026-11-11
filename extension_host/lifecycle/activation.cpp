// activation.cpp — Extension Activation Lifecycle
#include "../extension_manager.hpp"
#include "../vscode_api/commands.hpp"
#include "../vscode_api/workspace_api.hpp"
#include "../vscode_api/language_api.hpp"
#include "../vscode_api/debug_api.hpp"
#include "../vscode_api/terminal_api.hpp"
#include "../vscode_api/window_api.hpp"
#include "../vscode_api/editor_api.hpp"
#include <fstream>
#include <sstream>

namespace RawrXD {
namespace ExtensionHost {

// ============================================================================
// Extension Activation Manager
// ============================================================================
class ActivationManager {
public:
    static ActivationManager& Get();

    bool ActivateExtension(ExtensionInstance* instance);
    bool DeactivateExtension(ExtensionInstance* instance);

    // Activation events
    bool OnLanguage(const std::string& languageId);
    bool OnCommand(const std::string& commandId);
    bool OnWorkspaceContains(const std::string& filePattern);
    bool OnStartup();
    bool OnFileOpen(const std::string& extension);

private:
    ActivationManager() = default;
    std::map<std::string, bool> m_activatedExtensions;
};

ActivationManager& ActivationManager::Get() {
    static ActivationManager instance;
    return instance;
}

bool ActivationManager::ActivateExtension(ExtensionInstance* instance) {
    if (!instance) return false;
    if (instance->GetState() != ExtensionState::Activating) return false;

    const auto& manifest = instance->GetManifest();

    // Register commands from manifest
    // In production, parse contributes.commands from package.json
    auto& commands = VSCODE::Commands::Get();

    // Register language providers
    auto& language = VSCODE::Language::Get();

    // Register debug providers
    auto& debug = VSCODE::Debug::Get();

    // Execute extension's main entry point
    std::filesystem::path mainJs = manifest.installPath / "extension.js";
    if (std::filesystem::exists(mainJs)) {
        // TODO: Execute via QuickJS
        // QuickJSContext* ctx = static_cast<QuickJSContext*>(instance->GetRuntime());
        // qjs_eval(ctx, mainJs content);
    }

    m_activatedExtensions[manifest.id] = true;
    return instance->Activate();
}

bool ActivationManager::DeactivateExtension(ExtensionInstance* instance) {
    if (!instance) return false;
    m_activatedExtensions.erase(instance->GetManifest().id);
    return instance->Deactivate();
}

bool ActivationManager::OnLanguage(const std::string& languageId) {
    // TODO: Find extensions that activate on this language
    return false;
}

bool ActivationManager::OnCommand(const std::string& commandId) {
    // TODO: Find extensions that activate on this command
    return false;
}

bool ActivationManager::OnWorkspaceContains(const std::string& filePattern) {
    // TODO: Find extensions that activate when workspace contains file pattern
    return false;
}

bool ActivationManager::OnStartup() {
    // TODO: Activate * extensions
    return false;
}

bool ActivationManager::OnFileOpen(const std::string& extension) {
    // TODO: Activate extensions that handle this file extension
    return false;
}

} // namespace ExtensionHost
} // namespace RawrXD
