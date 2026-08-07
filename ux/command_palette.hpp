// command_palette.hpp — Command Palette Core
// Quick-open, fuzzy-search command execution interface
// Pure C++20 / Win32 — Zero Qt Dependencies
#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <mutex>
#include <algorithm>
#include <chrono>

namespace RawrXD {
namespace UX {

// ============================================================================
// Command Item
// ============================================================================
struct CommandItem {
    std::string id;
    std::string label;
    std::string description;
    std::string category;       // "File", "Edit", "View", "Run", "Terminal", "Help", etc.
    std::string keybinding;     // Display string like "Ctrl+Shift+P"
    std::string icon;           // Icon name
    std::vector<std::string> aliases;  // Alternative search terms
    bool enabled = true;
    bool hidden = false;        // Hidden from palette but still executable
    int order = 0;              // Sort order within category

    using Handler = std::function<void()>;
    Handler handler;
};

// ============================================================================
// Command Palette
// ============================================================================
class CommandPalette {
public:
    static CommandPalette& Get();

    // Register a command
    void RegisterCommand(const CommandItem& item);

    // Unregister a command
    void UnregisterCommand(const std::string& id);

    // Execute a command by ID
    bool Execute(const std::string& id);

    // Search commands by query (fuzzy match)
    std::vector<const CommandItem*> Search(const std::string& query, int maxResults = 20) const;

    // Get command by ID
    const CommandItem* GetCommand(const std::string& id) const;

    // List all commands
    std::vector<const CommandItem*> ListCommands() const;

    // List commands by category
    std::vector<const CommandItem*> ListByCategory(const std::string& category) const;

    // Get all categories
    std::vector<std::string> GetCategories() const;

    // Recently used commands
    std::vector<const CommandItem*> GetRecentCommands(int count = 10) const;
    void RecordCommandUse(const std::string& id);

    // Open palette (triggers UI to show)
    using PaletteOpenCallback = std::function<void()>;
    void SetOpenCallback(PaletteOpenCallback callback) { m_openCallback = callback; }
    void Open();

    // Built-in commands
    void RegisterBuiltinCommands();

private:
    CommandPalette() = default;

    // Fuzzy matching score
    double FuzzyScore(const std::string& text, const std::string& query) const;

    std::map<std::string, CommandItem> m_commands;
    std::vector<std::pair<std::string, std::chrono::steady_clock::time_point>> m_recentlyUsed;
    PaletteOpenCallback m_openCallback;
    mutable std::mutex m_mutex;
};

} // namespace UX
} // namespace RawrXD
