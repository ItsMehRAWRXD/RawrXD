// ============================================================================
// RawrXD Codex Menu Integration Implementation
// ============================================================================

#include "CodexMenuIntegration.hpp"

namespace RawrXD {
namespace Codex {

CodexMenuIntegration::CodexMenuIntegration() = default;
CodexMenuIntegration::~CodexMenuIntegration() = default;

bool CodexMenuIntegration::Initialize(std::shared_ptr<CodexSettingsManager> settings) {
    m_settings = settings;
    m_initialized = true;
    return true;
}

std::vector<CodexMenuItem> CodexMenuIntegration::BuildMenuBar() {
    std::vector<CodexMenuItem> menu;
    
    // Tools > Codex submenu
    menu.push_back(MakeSubmenu("codex_tools", "&Codex", GetCodexMenu()));
    
    return menu;
}

std::vector<CodexMenuItem> CodexMenuIntegration::BuildContextMenu() {
    std::vector<CodexMenuItem> menu;
    
    menu.push_back(MakeCommand("codex_complete", "&Complete", "Ctrl+Space",
        [this]() { OnCodexComplete(); }));
    menu.push_back(MakeCommand("codex_explain", "&Explain", "Ctrl+Shift+E",
        [this]() { OnCodexExplain(); }));
    menu.push_back(MakeCommand("codex_refactor", "&Refactor...", "Ctrl+Shift+R",
        [this]() { OnCodexRefactor(); }));
    menu.push_back(MakeSeparator());
    menu.push_back(MakeCommand("codex_generate_tests", "&Generate Tests", "Ctrl+Shift+T",
        [this]() { OnCodexGenerateTests(); }));
    menu.push_back(MakeCommand("codex_fix", "&Fix Errors", "Ctrl+Shift+F",
        [this]() { OnCodexFixErrors(); }));
    menu.push_back(MakeSeparator());
    menu.push_back(MakeCommand("codex_chat", "Open Codex &Chat", "Ctrl+Shift+C",
        [this]() { OnCodexChat(); }));
    
    return menu;
}

std::vector<CodexMenuItem> CodexMenuIntegration::BuildToolbar() {
    std::vector<CodexMenuItem> toolbar;
    
    toolbar.push_back(MakeCommand("codex_complete", "Complete", "Ctrl+Space",
        [this]() { OnCodexComplete(); }));
    toolbar.push_back(MakeCommand("codex_explain", "Explain", "",
        [this]() { OnCodexExplain(); }));
    toolbar.push_back(MakeCommand("codex_chat", "Chat", "",
        [this]() { OnCodexChat(); }));
    toolbar.push_back(MakeSeparator());
    toolbar.push_back(MakeCommand("codex_settings", "Settings", "",
        [this]() { OnCodexSettings(); }));
    
    return toolbar;
}

std::vector<CodexMenuItem> CodexMenuIntegration::GetCodexMenu() {
    std::vector<CodexMenuItem> menu;
    
    // AI Actions
    menu.push_back(MakeCommand("codex_complete", "&Complete at Cursor", "Ctrl+Shift+L",
        [this]() { OnCodexComplete(); }));
    menu.push_back(MakeCommand("codex_explain", "&Explain Selection", "Ctrl+Shift+E",
        [this]() { OnCodexExplain(); }));
    menu.push_back(MakeCommand("codex_refactor", "&Refactor...", "Ctrl+Shift+R",
        [this]() { OnCodexRefactor(); }));
    menu.push_back(MakeSeparator());
    
    // Code Generation
    menu.push_back(MakeCommand("codex_generate_tests", "&Generate Tests", "Ctrl+Shift+T",
        [this]() { OnCodexGenerateTests(); }));
    menu.push_back(MakeCommand("codex_fix", "&Fix Errors", "Ctrl+Shift+F",
        [this]() { OnCodexFixErrors(); }));
    menu.push_back(MakeCommand("codex_optimize", "&Optimize Code", "Ctrl+Shift+O",
        [this]() { OnCodexOptimize(); }));
    menu.push_back(MakeSeparator());
    
    // Chat & Settings
    menu.push_back(MakeCommand("codex_chat", "Open &Chat Panel", "Ctrl+Shift+C",
        [this]() { OnCodexChat(); }));
    menu.push_back(MakeSeparator());
    menu.push_back(MakeCommand("codex_settings", "&Settings...", "",
        [this]() { OnCodexSettings(); }));
    
    return menu;
}

std::vector<CodexMenuItem> CodexMenuIntegration::GetEditMenuItems() {
    std::vector<CodexMenuItem> items;
    
    items.push_back(MakeSeparator());
    items.push_back(MakeCommand("codex_complete", "Codex: &Complete", "Ctrl+Shift+L",
        [this]() { OnCodexComplete(); }));
    items.push_back(MakeCommand("codex_explain", "Codex: &Explain", "Ctrl+Shift+E",
        [this]() { OnCodexExplain(); }));
    
    return items;
}

std::vector<CodexMenuItem> CodexMenuIntegration::GetViewMenuItems() {
    std::vector<CodexMenuItem> items;
    
    items.push_back(MakeSeparator());
    items.push_back(MakeCommand("codex_chat", "Codex &Chat Panel", "Ctrl+Shift+C",
        [this]() { OnCodexChat(); }));
    
    return items;
}

std::vector<CodexMenuItem> CodexMenuIntegration::GetHelpMenuItems() {
    std::vector<CodexMenuItem> items;
    
    items.push_back(MakeSeparator());
    items.push_back(MakeCommand("codex_docs", "Codex &Documentation", "",
        []() { /* Open docs */ }));
    items.push_back(MakeCommand("codex_about", "&About Codex", "",
        []() { /* Show about */ }));
    
    return items;
}

std::vector<CodexMenuItem> CodexMenuIntegration::GetEditorContextMenu(const std::string& selectedText) {
    std::vector<CodexMenuItem> menu;
    
    bool hasSelection = !selectedText.empty();
    
    menu.push_back(MakeSeparator());
    menu.push_back(MakeCommand("codex_complete", "Codex: Complete", "",
        [this]() { OnCodexComplete(); }));
    
    if (hasSelection) {
        menu.push_back(MakeCommand("codex_explain", "Codex: Explain Selection", "",
            [this]() { OnCodexExplain(); }));
        menu.push_back(MakeCommand("codex_refactor", "Codex: Refactor...", "",
            [this]() { OnCodexRefactor(); }));
    }
    
    return menu;
}

std::vector<CodexMenuItem> CodexMenuIntegration::GetChatContextMenu() {
    std::vector<CodexMenuItem> menu;
    
    menu.push_back(MakeCommand("codex_chat_clear", "&Clear History", "",
        []() { /* Clear chat */ }));
    menu.push_back(MakeCommand("codex_chat_export", "&Export Chat...", "",
        []() { /* Export chat */ }));
    menu.push_back(MakeSeparator());
    menu.push_back(MakeCommand("codex_settings", "&Settings...", "",
        [this]() { OnCodexSettings(); }));
    
    return menu;
}

void CodexMenuIntegration::OnCodexComplete() {
    // Triggered by Ctrl+Shift+L or menu
    // IDE should call GetCodexAutocompleteProvider()->ProvideCompletions()
}

void CodexMenuIntegration::OnCodexExplain() {
    // Explain selected code
    // IDE should call GetCodexLSPBridge()->ExplainCode()
}

void CodexMenuIntegration::OnCodexRefactor() {
    // Show refactor dialog
    // IDE should prompt for instruction then call GetCodexLSPBridge()->RefactorCode()
}

void CodexMenuIntegration::OnCodexGenerateTests() {
    // Generate tests for selected code
    // IDE should call GetCodexLSPBridge()->GenerateTests()
}

void CodexMenuIntegration::OnCodexFixErrors() {
    // Fix errors in selected code
    // IDE should call GetCodexLSPBridge()->FixErrors()
}

void CodexMenuIntegration::OnCodexOptimize() {
    // Optimize selected code
    // IDE should call GetCodexLSPBridge()->RefactorCode() with "optimize" instruction
}

void CodexMenuIntegration::OnCodexChat() {
    // Open/show chat panel
    // IDE should show Codex chat panel
}

void CodexMenuIntegration::OnCodexSettings() {
    // Show settings dialog
    // IDE should show CodexSettingsDialog
}

void CodexMenuIntegration::OnCodexToggleInline() {
    // Toggle inline completions
    if (m_settings) {
        auto& s = m_settings->GetSettingsMutable();
        s.enableInlineCompletions = !s.enableInlineCompletions;
        m_settings->SetEnableInlineCompletions(s.enableInlineCompletions);
    }
}

void CodexMenuIntegration::OnCodexToggleChat() {
    // Toggle chat panel
    if (m_settings) {
        auto& s = m_settings->GetSettingsMutable();
        s.enableChat = !s.enableChat;
        m_settings->SetEnableChat(s.enableChat);
    }
}

int CodexMenuIntegration::GetCommandId(const std::string& command) {
    auto it = m_commandIds.find(command);
    if (it != m_commandIds.end()) {
        return it->second;
    }
    return RegisterCommand(command);
}

std::vector<CodexMenuIntegration::Shortcut> CodexMenuIntegration::GetDefaultShortcuts() {
    std::vector<Shortcut> shortcuts;
    
    shortcuts.push_back({"codex_complete", "Ctrl+Shift+L", GetCommandId("codex_complete")});
    shortcuts.push_back({"codex_explain", "Ctrl+Shift+E", GetCommandId("codex_explain")});
    shortcuts.push_back({"codex_refactor", "Ctrl+Shift+R", GetCommandId("codex_refactor")});
    shortcuts.push_back({"codex_generate_tests", "Ctrl+Shift+T", GetCommandId("codex_generate_tests")});
    shortcuts.push_back({"codex_fix", "Ctrl+Shift+F", GetCommandId("codex_fix")});
    shortcuts.push_back({"codex_optimize", "Ctrl+Shift+O", GetCommandId("codex_optimize")});
    shortcuts.push_back({"codex_chat", "Ctrl+Shift+C", GetCommandId("codex_chat")});
    
    return shortcuts;
}

CodexMenuItem CodexMenuIntegration::MakeCommand(const std::string& id, const std::string& label,
                                                   const std::string& shortcut,
                                                   std::function<void()> handler) {
    CodexMenuItem item;
    item.id = id;
    item.label = label;
    item.shortcut = shortcut;
    item.type = CodexMenuItemType::Command;
    item.handler = handler;
    return item;
}

CodexMenuItem CodexMenuIntegration::MakeSeparator() {
    CodexMenuItem item;
    item.type = CodexMenuItemType::Separator;
    return item;
}

CodexMenuItem CodexMenuIntegration::MakeSubmenu(const std::string& id, const std::string& label,
                                                   std::vector<CodexMenuItem> children) {
    CodexMenuItem item;
    item.id = id;
    item.label = label;
    item.type = CodexMenuItemType::Submenu;
    item.children = std::move(children);
    return item;
}

CodexMenuItem CodexMenuIntegration::MakeCheckbox(const std::string& id, const std::string& label,
                                                  bool checked, std::function<void()> handler) {
    CodexMenuItem item;
    item.id = id;
    item.label = label;
    item.type = CodexMenuItemType::Checkbox;
    item.checked = checked;
    item.handler = handler;
    return item;
}

int CodexMenuIntegration::RegisterCommand(const std::string& id) {
    int cmdId = m_nextCommandId++;
    m_commandIds[id] = cmdId;
    return cmdId;
}

} // namespace Codex
} // namespace RawrXD
