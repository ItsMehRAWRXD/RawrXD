#include "command_registry.h"
#include "application.h"
#include <windows.h>
#include <algorithm>
#include <sstream>
#include <ctype.h>

namespace RawrXD {

CommandRegistry& CommandRegistry::Instance() {
    static CommandRegistry instance;
    return instance;
}

bool CommandRegistry::RegisterCommand(const Command& command) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (commands_.find(command.id) != commands_.end()) {
        return false; // Already registered
    }
    
    commands_[command.id] = command;
    
    // Register keybinding if provided
    if (!command.keybinding.empty()) {
        keybindings_[command.keybinding] = command.id;
    }
    
    return true;
}

bool CommandRegistry::UnregisterCommand(const std::string& commandId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = commands_.find(commandId);
    if (it == commands_.end()) {
        return false;
    }
    
    // Remove keybinding
    if (!it->second.keybinding.empty()) {
        keybindings_.erase(it->second.keybinding);
    }
    
    commands_.erase(it);
    return true;
}

bool CommandRegistry::HasCommand(const std::string& commandId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return commands_.find(commandId) != commands_.end();
}

bool CommandRegistry::ExecuteCommand(const std::string& commandId, const std::vector<std::string>& args) {
    CommandContext context;
    context.commandId = commandId;
    context.arguments = args;
    return ExecuteCommand(commandId, context);
}

bool CommandRegistry::ExecuteCommand(const std::string& commandId, CommandContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = commands_.find(commandId);
    if (it == commands_.end()) {
        context.errorMessage = "Command not found: " + commandId;
        return false;
    }
    
    const Command& cmd = it->second;
    
    if (!cmd.enabled) {
        context.errorMessage = "Command is disabled: " + commandId;
        return false;
    }
    
    // Check context conditions
    if (!CheckConditions(cmd.when)) {
        context.errorMessage = "Command not available in current context";
        return false;
    }
    
    if (!cmd.handler) {
        context.errorMessage = "Command has no handler: " + commandId;
        return false;
    }
    
    // Execute handler
    cmd.handler(context);
    context.handled = true;
    
    return true;
}

std::vector<Command> CommandRegistry::GetAllCommands() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Command> result;
    for (const auto& [id, cmd] : commands_) {
        if (cmd.visible) {
            result.push_back(cmd);
        }
    }
    return result;
}

std::vector<CommandPaletteItem> CommandRegistry::SearchCommands(const std::string& query) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<CommandPaletteItem> results;
    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
    
    for (const auto& [id, cmd] : commands_) {
        if (!cmd.visible || !cmd.enabled) continue;
        
        // Check if command matches query
        std::string lowerTitle = cmd.title;
        std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::tolower);
        std::string lowerCategory = cmd.category;
        std::transform(lowerCategory.begin(), lowerCategory.end(), lowerCategory.begin(), ::tolower);
        
        int score = 0;
        
        // Exact match
        if (lowerTitle == lowerQuery) {
            score = 100;
        }
        // Starts with
        else if (lowerTitle.find(lowerQuery) == 0) {
            score = 80;
        }
        // Contains
        else if (lowerTitle.find(lowerQuery) != std::string::npos) {
            score = 60;
        }
        // Category match
        else if (lowerCategory.find(lowerQuery) != std::string::npos) {
            score = 40;
        }
        // ID match
        else if (id.find(lowerQuery) != std::string::npos) {
            score = 20;
        }
        
        if (score > 0) {
            CommandPaletteItem item;
            item.id = cmd.id;
            item.title = cmd.title;
            item.category = cmd.category;
            item.keybinding = cmd.keybinding;
            item.icon = cmd.icon;
            item.score = score;
            results.push_back(item);
        }
    }
    
    // Sort by score descending
    std::sort(results.begin(), results.end(),
        [](const CommandPaletteItem& a, const CommandPaletteItem& b) {
            return a.score > b.score;
        });
    
    return results;
}

const Command* CommandRegistry::GetCommand(const std::string& commandId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = commands_.find(commandId);
    if (it != commands_.end()) {
        return &it->second;
    }
    return nullptr;
}

void CommandRegistry::RegisterKeybinding(const std::string& keybinding, const std::string& commandId) {
    std::lock_guard<std::mutex> lock(mutex_);
    keybindings_[keybinding] = commandId;
}

void CommandRegistry::UnregisterKeybinding(const std::string& keybinding) {
    std::lock_guard<std::mutex> lock(mutex_);
    keybindings_.erase(keybinding);
}

std::string CommandRegistry::GetCommandForKeybinding(const std::string& keybinding) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = keybindings_.find(keybinding);
    if (it != keybindings_.end()) {
        return it->second;
    }
    return "";
}

std::vector<std::pair<std::string, std::string>> CommandRegistry::GetAllKeybindings() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::pair<std::string, std::string>> result;
    for (const auto& [keybinding, commandId] : keybindings_) {
        result.push_back({keybinding, commandId});
    }
    return result;
}

void CommandRegistry::SetContext(const std::string& key, bool value) {
    std::lock_guard<std::mutex> lock(mutex_);
    context_[key] = value;
}

bool CommandRegistry::GetContext(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = context_.find(key);
    if (it != context_.end()) {
        return it->second;
    }
    return false;
}

void CommandRegistry::ClearContext(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    context_.erase(key);
}

void CommandRegistry::RegisterBuiltInCommands() {
    // File commands
    RegisterCommand({
        Commands::FileNew,
        "New File",
        "File",
        "Ctrl+N",
        "",
        true, true,
        [](CommandContext& ctx) {
            // TODO: Create new file
            MessageBoxA(nullptr, "New File command executed", "RawrXD", MB_OK);
        }
    });
    
    RegisterCommand({
        Commands::FileOpen,
        "Open File",
        "File",
        "Ctrl+O",
        "",
        true, true,
        [](CommandContext& ctx) {
            // TODO: Open file dialog
            MessageBoxA(nullptr, "Open File command executed", "RawrXD", MB_OK);
        }
    });
    
    RegisterCommand({
        Commands::FileSave,
        "Save",
        "File",
        "Ctrl+S",
        "",
        true, true,
        [](CommandContext& ctx) {
            // TODO: Save current file
            MessageBoxA(nullptr, "Save command executed", "RawrXD", MB_OK);
        }
    });
    
    // Edit commands
    RegisterCommand({
        Commands::EditUndo,
        "Undo",
        "Edit",
        "Ctrl+Z",
        "",
        true, true,
        [](CommandContext& ctx) {
            // TODO: Undo
        }
    });
    
    RegisterCommand({
        Commands::EditRedo,
        "Redo",
        "Edit",
        "Ctrl+Y",
        "",
        true, true,
        [](CommandContext& ctx) {
            // TODO: Redo
        }
    });
    
    // View commands
    RegisterCommand({
        Commands::ViewCommandPalette,
        "Command Palette",
        "View",
        "Ctrl+Shift+P",
        "",
        true, true,
        [](CommandContext& ctx) {
            Application::Instance().ShowCommandPalette();
        }
    });
    
    RegisterCommand({
        Commands::ViewToggleTerminal,
        "Toggle Terminal",
        "View",
        "Ctrl+`",
        "",
        true, true,
        [](CommandContext& ctx) {
            // TODO: Toggle terminal visibility
        }
    });
    
    // Go commands
    RegisterCommand({
        Commands::GoToFile,
        "Go to File",
        "Go",
        "Ctrl+P",
        "",
        true, true,
        [](CommandContext& ctx) {
            // TODO: Quick open
        }
    });
    
    // Task commands
    RegisterCommand({
        Commands::TasksRunBuild,
        "Run Build Task",
        "Tasks",
        "Ctrl+Shift+B",
        "",
        true, true,
        [](CommandContext& ctx) {
            auto* tasks = Application::Instance().GetTaskRunner();
            if (tasks) {
                tasks->RunBuildTask();
            }
        }
    });
    
    // AI commands
    RegisterCommand({
        Commands::AIComplete,
        "AI: Complete Code",
        "AI",
        "Ctrl+Space",
        "",
        true, true,
        [](CommandContext& ctx) {
            // TODO: Trigger AI completion
        }
    });
    
    RegisterCommand({
        Commands::AIChat,
        "AI: Open Chat",
        "AI",
        "Ctrl+Shift+L",
        "",
        true, true,
        [](CommandContext& ctx) {
            // TODO: Open AI chat panel
        }
    });
}

void CommandRegistry::RegisterExtensionCommands(const std::string& extensionId) {
    // TODO: Load commands from extension manifest
}

void CommandRegistry::UnregisterExtensionCommands(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = extensionCommands_.find(extensionId);
    if (it == extensionCommands_.end()) return;
    
    for (const auto& cmdId : it->second) {
        commands_.erase(cmdId);
    }
    
    extensionCommands_.erase(it);
}

bool CommandRegistry::CheckConditions(const std::vector<std::string>& conditions) const {
    for (const auto& condition : conditions) {
        auto it = context_.find(condition);
        if (it == context_.end() || !it->second) {
            return false;
        }
    }
    return true;
}

} // namespace RawrXD