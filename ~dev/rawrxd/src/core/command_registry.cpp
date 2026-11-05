#include "command_registry.h"
#ifndef RAWRXD_COMMAND_REGISTRY_HEADLESS
#include "application.h"
#include <windows.h>
#include <commdlg.h>
#endif
#include <algorithm>
#include <sstream>
#include <ctype.h>
#include <fstream>
#include <exception>

#if defined(_MSC_VER) && !defined(RAWRXD_COMMAND_REGISTRY_HEADLESS)
#pragma comment(lib, "comdlg32.lib")
#endif

namespace RawrXD {

CommandRegistry& CommandRegistry::Instance() {
    static CommandRegistry instance;
    return instance;
}

bool CommandRegistry::RegisterCommand(const Command& command) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (command.id.empty() || !command.handler ||
        commands_.find(command.id) != commands_.end()) {
        return false; // Invalid or already registered
    }
    
    commands_[command.id] = command;
    
    // Reject conflicting bindings instead of silently stealing another command's shortcut.
    if (!command.keybinding.empty()) {
        const auto binding = keybindings_.find(command.keybinding);
        if (binding != keybindings_.end() && binding->second != command.id) {
            commands_.erase(command.id);
            return false;
        }
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
        const auto bindingIt = keybindings_.find(it->second.keybinding);
        if (bindingIt != keybindings_.end() && bindingIt->second == commandId) {
            keybindings_.erase(bindingIt);
        }
    }
    
    commands_.erase(it);
    // A direct unregister must also detach extension ownership so that
    // unloading an extension cannot later remove a reused command ID.
    for (auto owner = extensionCommands_.begin(); owner != extensionCommands_.end();) {
        auto& ids = owner->second;
        ids.erase(std::remove(ids.begin(), ids.end(), commandId), ids.end());
        if (ids.empty()) owner = extensionCommands_.erase(owner);
        else ++owner;
    }
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
    CommandHandler handler;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = commands_.find(commandId);
        if (it == commands_.end()) {
            context.errorMessage = "Command not found: " + commandId;
            return false;
        }
        const Command& cmd = it->second;
        if (!cmd.enabled) {
            context.errorMessage = "Command is disabled: " + commandId;
            return false;
        }
        if (!CheckConditions(cmd.when)) {
            context.errorMessage = "Command not available in current context";
            return false;
        }
        if (!cmd.handler) {
            context.errorMessage = "Command has no handler: " + commandId;
            return false;
        }
        // Copy the handler under the lock, then invoke outside it.
        // Handlers can call SetContext, register commands, or dispatch nested commands.
        handler = cmd.handler;
    }

    try {
        handler(context);
    } catch (const std::exception& ex) {
        context.errorMessage = std::string("Command handler exception: ") + ex.what();
        return false;
    } catch (...) {
        context.errorMessage = "Command handler threw an unknown exception";
        return false;
    }
    // Built-in handlers historically leave handled unset on success.
    // Preserve that contract until each handler is migrated and tested.
    if (!context.errorMessage.empty()) return false;
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

#ifndef RAWRXD_COMMAND_REGISTRY_HEADLESS
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
            // Create new untitled file
            auto& app = Application::Instance();
            // Generate unique filename
            static int untitledCount = 1;
            std::string filename = "Untitled-" + std::to_string(untitledCount++) + ".txt";
            
            // Create empty file in temp directory
            char tempPath[MAX_PATH];
            GetTempPathA(MAX_PATH, tempPath);
            std::string fullPath = std::string(tempPath) + "\\" + filename;
            
            std::ofstream file(fullPath);
            if (file.is_open()) {
                file.close();
                // Notify application to open the new file
                // In full implementation, would integrate with document manager
                MessageBoxA(nullptr, ("Created new file: " + fullPath).c_str(), "RawrXD", MB_OK);
            } else {
                MessageBoxA(nullptr, "Failed to create new file", "RawrXD", MB_OK | MB_ICONERROR);
            }
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
            // Open file dialog
            char filename[MAX_PATH] = {0};
            OPENFILENAMEA ofn = {0};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = nullptr;
            ofn.lpstrFilter = "All Files\0*.*\0Text Files\0*.txt\0C++ Files\0*.cpp;*.h;*.hpp\0";
            ofn.lpstrFile = filename;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            
            if (GetOpenFileNameA(&ofn)) {
                // File selected, open it
                // In full implementation, would integrate with document manager
                MessageBoxA(nullptr, ("Opening file: " + std::string(filename)).c_str(), "RawrXD", MB_OK);
                
                // Store in context for potential use
                ctx.Set("lastOpenedFile", filename);
            }
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
            // Save current file
            // In full implementation, would get current document and save
            std::string currentFile = ctx.Get("currentFile");
            if (currentFile.empty()) {
                // No current file, use Save As
                char filename[MAX_PATH] = {0};
                OPENFILENAMEA ofn = {0};
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = nullptr;
                ofn.lpstrFilter = "All Files\0*.*\0";
                ofn.lpstrFile = filename;
                ofn.nMaxFile = MAX_PATH;
                ofn.Flags = OFN_OVERWRITEPROMPT;
                
                if (GetSaveFileNameA(&ofn)) {
                    currentFile = filename;
                    ctx.Set("currentFile", currentFile);
                } else {
                    return; // User cancelled
                }
            }
            
            // In full implementation, would get content from editor and save
            MessageBoxA(nullptr, ("Saved file: " + currentFile).c_str(), "RawrXD", MB_OK);
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

#else
void CommandRegistry::RegisterBuiltInCommands() {
    // Headless acceptance intentionally excludes Win32 application commands.
}
#endif

bool CommandRegistry::RegisterExtensionCommand(
    const std::string& extensionId, const Command& command) {
    if (extensionId.empty() || command.id.empty() || !command.handler) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    if (commands_.find(command.id) != commands_.end()) return false;
    if (!command.keybinding.empty()) {
        const auto binding = keybindings_.find(command.keybinding);
        if (binding != keybindings_.end() && binding->second != command.id) {
            return false;
        }
    }
    commands_.emplace(command.id, command);
    extensionCommands_[extensionId].push_back(command.id);
    if (!command.keybinding.empty()) keybindings_[command.keybinding] = command.id;
    return true;
}

void CommandRegistry::RegisterExtensionCommands(const std::string& extensionId) {
    // Legacy no-argument entry point cannot infer contributed commands.
    // Registration must supply a concrete Command and handler.
    (void)extensionId;
}

void CommandRegistry::UnregisterExtensionCommands(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = extensionCommands_.find(extensionId);
    if (it == extensionCommands_.end()) return;
    
    for (const auto& cmdId : it->second) {
        const auto commandIt = commands_.find(cmdId);
        if (commandIt == commands_.end()) continue;
        if (!commandIt->second.keybinding.empty()) {
            const auto bindingIt = keybindings_.find(commandIt->second.keybinding);
            if (bindingIt != keybindings_.end() && bindingIt->second == cmdId) {
                keybindings_.erase(bindingIt);
            }
        }
        commands_.erase(commandIt);
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
