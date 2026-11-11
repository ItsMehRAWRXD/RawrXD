#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <mutex>

namespace RawrXD {

// Command context - passed to command handlers
struct CommandContext {
    std::string commandId;
    std::vector<std::string> arguments;
    bool handled = false;
    std::string errorMessage;
    
    // Source of the command invocation
    enum class Source {
        CommandPalette,
        KeyboardShortcut,
        Menu,
        Extension,
        API,
        Agent
    } source = Source::CommandPalette;
};

// Command handler type
using CommandHandler = std::function<void(CommandContext&)>;

// Command definition
struct Command {
    std::string id;
    std::string title;
    std::string category;  // For grouping in command palette
    std::string keybinding; // Default keybinding (e.g., "Ctrl+Shift+P")
    std::string icon;       // Icon identifier
    bool enabled = true;
    bool visible = true;
    CommandHandler handler;
    std::vector<std::string> when; // Context conditions (e.g., "editorTextFocus")
};

// Command palette item (for UI)
struct CommandPaletteItem {
    std::string id;
    std::string title;
    std::string category;
    std::string keybinding;
    std::string icon;
    int score = 0;  // Search relevance score
};

// Command Registry - Central command management
class CommandRegistry {
public:
    static CommandRegistry& Instance();
    
    // Registration
    bool RegisterCommand(const Command& command);
    bool UnregisterCommand(const std::string& commandId);
    bool HasCommand(const std::string& commandId) const;
    
    // Execution
    bool ExecuteCommand(const std::string& commandId, const std::vector<std::string>& args = {});
    bool ExecuteCommand(const std::string& commandId, CommandContext& context);
    
    // Query
    std::vector<Command> GetAllCommands() const;
    std::vector<CommandPaletteItem> SearchCommands(const std::string& query) const;
    const Command* GetCommand(const std::string& commandId) const;
    
    // Keybindings
    void RegisterKeybinding(const std::string& keybinding, const std::string& commandId);
    void UnregisterKeybinding(const std::string& keybinding);
    std::string GetCommandForKeybinding(const std::string& keybinding) const;
    std::vector<std::pair<std::string, std::string>> GetAllKeybindings() const;
    
    // Context conditions
    void SetContext(const std::string& key, bool value);
    bool GetContext(const std::string& key) const;
    void ClearContext(const std::string& key);
    
    // Built-in commands
    void RegisterBuiltInCommands();
    
    // Extension commands
    void RegisterExtensionCommands(const std::string& extensionId);
    void UnregisterExtensionCommands(const std::string& extensionId);
    
private:
    CommandRegistry() = default;
    ~CommandRegistry() = default;
    
    std::map<std::string, Command> commands_;
    std::map<std::string, std::string> keybindings_;  // keybinding -> commandId
    std::map<std::string, bool> context_;
    std::map<std::string, std::vector<std::string>> extensionCommands_;  // extensionId -> commandIds
    
    mutable std::mutex mutex_;
    
    bool CheckConditions(const std::vector<std::string>& conditions) const;
    int CalculateScore(const Command& cmd, const std::string& query) const;
};

// Built-in command IDs
namespace Commands {
    // File
    constexpr const char* FileNew = "file.newFile";
    constexpr const char* FileOpen = "file.openFile";
    constexpr const char* FileSave = "file.save";
    constexpr const char* FileSaveAll = "file.saveAll";
    constexpr const char* FileClose = "file.closeFile";
    constexpr const char* FileExit = "file.exit";
    
    // Edit
    constexpr const char* EditUndo = "edit.undo";
    constexpr const char* EditRedo = "edit.redo";
    constexpr const char* EditCut = "edit.cut";
    constexpr const char* EditCopy = "edit.copy";
    constexpr const char* EditPaste = "edit.paste";
    constexpr const char* EditFind = "edit.find";
    constexpr const char* EditReplace = "edit.replace";
    
    // View
    constexpr const char* ViewCommandPalette = "view.commandPalette";
    constexpr const char* ViewToggleSidebar = "view.toggleSidebar";
    constexpr const char* ViewTogglePanel = "view.togglePanel";
    constexpr const char* ViewToggleTerminal = "view.toggleTerminal";
    
    // Go
    constexpr const char* GoToFile = "workbench.action.quickOpen";
    constexpr const char* GoToSymbol = "workbench.action.gotoSymbol";
    constexpr const char* GoToLine = "workbench.action.gotoLine";
    constexpr const char* GoBack = "workbench.action.navigateBack";
    constexpr const char* GoForward = "workbench.action.navigateForward";
    
    // Workbench
    constexpr const char* WorkbenchOpenSettings = "workbench.action.openSettings";
    constexpr const char* WorkbenchOpenKeyboardShortcuts = "workbench.action.openGlobalKeybindings";
    constexpr const char* WorkbenchReloadWindow = "workbench.action.reloadWindow";
    constexpr const char* WorkbenchToggleDevTools = "workbench.action.toggleDevTools";
    
    // Tasks
    constexpr const char* TasksRunBuild = "workbench.action.tasks.build";
    constexpr const char* TasksRunTest = "workbench.action.tasks.test";
    constexpr const char* TasksConfigure = "workbench.action.tasks.configureTaskRunner";
    
    // Extensions
    constexpr const char* ExtensionsShowInstalled = "workbench.view.extensions";
    constexpr const char* ExtensionsInstallFromVSIX = "workbench.extensions.action.installFromVSIX";
    
    // AI/Agent
    constexpr const char* AIComplete = "rawrxd.ai.complete";
    constexpr const char* AIExplain = "rawrxd.ai.explain";
    constexpr const char* AIFix = "rawrxd.ai.fix";
    constexpr const char* AIChat = "rawrxd.ai.chat";
    constexpr const char* AgentStart = "rawrxd.agent.start";
    constexpr const char* AgentStop = "rawrxd.agent.stop";
}

} // namespace RawrXD