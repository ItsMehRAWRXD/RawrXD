// test_extension_host.cpp — Compilation test for extension_host
#include "extension_manager.hpp"
#include "vscode_api/commands.hpp"
#include "vscode_api/workspace_api.hpp"
#include "vscode_api/editor_api.hpp"
#include "vscode_api/window_api.hpp"
#include "vscode_api/language_api.hpp"
#include "vscode_api/debug_api.hpp"
#include "vscode_api/terminal_api.hpp"
#include "sandbox/extension_sandbox.hpp"
#include "sandbox/permission_bridge.hpp"
#include "marketplace/vsix_loader.hpp"
#include "marketplace/manifest_parser.hpp"
#include "marketplace/registry.hpp"

int main() {
    // Test ExtensionManager
    RawrXD::ExtensionHost::ExtensionManager mgr;
    mgr.Initialize("d:\\rawrxd\\extensions");

    // Test VS Code API singletons
    auto& cmds = RawrXD::ExtensionHost::VSCODE::Commands::Get();
    auto& ws = RawrXD::ExtensionHost::VSCODE::Workspace::Get();
    auto& editor = RawrXD::ExtensionHost::VSCODE::Editor::Get();
    auto& window = RawrXD::ExtensionHost::VSCODE::Window::Get();
    auto& lang = RawrXD::ExtensionHost::VSCODE::Language::Get();
    auto& debug = RawrXD::ExtensionHost::VSCODE::Debug::Get();
    auto& termMgr = RawrXD::ExtensionHost::VSCODE::TerminalManager::Get();

    // Test Sandbox
    RawrXD::ExtensionHost::SandboxConfig config;
    RawrXD::ExtensionHost::ExtensionSandbox sandbox(config);
    sandbox.Initialize();

    // Test PermissionBridge
    auto& perms = RawrXD::ExtensionHost::PermissionBridge::Get();

    // Test Marketplace
    auto manifest = RawrXD::ExtensionHost::ManifestParser::Parse("d:\\rawrxd\\extensions\\test\\package.json");
    auto& registry = RawrXD::ExtensionHost::ExtensionRegistry::Get();
    registry.Initialize("d:\\rawrxd\\extensions\\registry.json");

    return 0;
}
