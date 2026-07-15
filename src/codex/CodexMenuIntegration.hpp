// ============================================================================
// RawrXD Codex Menu Integration
// Menu, toolbar, and keyboard shortcut integration for IDE
// ============================================================================

#pragma once
#include "CodexCLI.hpp"
#include "CodexSettings.hpp"
#include <functional>
#include <vector>
#include <string>

namespace RawrXD {
namespace Codex {

// Menu item types
enum class CodexMenuItemType {
    Command,    // Direct command
    Separator,  // Menu separator
    Submenu,    // Submenu container
    Checkbox,   // Toggle item
    Radio       // Radio button group
};

// Menu item structure
struct CodexMenuItem {
    std::string id;           // Unique identifier
    std::string label;        // Display text (& for accelerator)
    std::string shortcut;     // Keyboard shortcut (e.g., "Ctrl+Shift+C")
    CodexMenuItemType type;
    std::function<void()> handler;
    bool enabled = true;
    bool checked = false;
    std::vector<CodexMenuItem> children;  // For submenus
};

// Codex Menu Integration - provides IDE menu structure
class CodexMenuIntegration {
public:
    CodexMenuIntegration();
    ~CodexMenuIntegration();

    // Initialize with settings
    bool Initialize(std::shared_ptr<CodexSettingsManager> settings);

    // Build complete menu structure
    std::vector<CodexMenuItem> BuildMenuBar();
    std::vector<CodexMenuItem> BuildContextMenu();
    std::vector<CodexMenuItem> BuildToolbar();

    // Individual menu sections
    std::vector<CodexMenuItem> GetCodexMenu();        // Tools > Codex
    std::vector<CodexMenuItem> GetEditMenuItems();    // Edit > Codex actions
    std::vector<CodexMenuItem> GetViewMenuItems();    // View > Codex panel
    std::vector<CodexMenuItem> GetHelpMenuItems();    // Help > Codex

    // Context menu providers
    std::vector<CodexMenuItem> GetEditorContextMenu(const std::string& selectedText);
    std::vector<CodexMenuItem> GetChatContextMenu();

    // Command handlers (called by IDE)
    void OnCodexComplete();
    void OnCodexExplain();
    void OnCodexRefactor();
    void OnCodexGenerateTests();
    void OnCodexFixErrors();
    void OnCodexOptimize();
    void OnCodexChat();
    void OnCodexSettings();
    void OnCodexToggleInline();
    void OnCodexToggleChat();

    // Get command ID for menu registration
    int GetCommandId(const std::string& command);

    // Keyboard shortcuts
    struct Shortcut {
        std::string command;
        std::string keyCombo;  // e.g., "Ctrl+Shift+C"
        int commandId;
    };
    std::vector<Shortcut> GetDefaultShortcuts();

private:
    std::shared_ptr<CodexSettingsManager> m_settings;
    bool m_initialized = false;
    int m_nextCommandId = 5000;  // Starting command ID

    // Command ID map
    std::map<std::string, int> m_commandIds;

    // Helper methods
    CodexMenuItem MakeCommand(const std::string& id, const std::string& label,
                               const std::string& shortcut,
                               std::function<void()> handler);
    CodexMenuItem MakeSeparator();
    CodexMenuItem MakeSubmenu(const std::string& id, const std::string& label,
                               std::vector<CodexMenuItem> children);
    CodexMenuItem MakeCheckbox(const std::string& id, const std::string& label,
                                bool checked, std::function<void()> handler);

    int RegisterCommand(const std::string& id);
};

} // namespace Codex
} // namespace RawrXD
