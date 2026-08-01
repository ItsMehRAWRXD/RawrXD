// command_palette.cpp — Command Palette Implementation
#include "command_palette.hpp"
#include <regex>
#include <cmath>

namespace RawrXD {
namespace UX {

CommandPalette& CommandPalette::Get() {
    static CommandPalette instance;
    return instance;
}

void CommandPalette::RegisterCommand(const CommandItem& item) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_commands[item.id] = item;
}

void CommandPalette::UnregisterCommand(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_commands.erase(id);
}

bool CommandPalette::Execute(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_commands.find(id);
    if (it == m_commands.end() || !it->second.enabled) return false;

    if (it->second.handler) {
        RecordCommandUse(id);
        it->second.handler();
        return true;
    }
    return false;
}

std::vector<const CommandItem*> CommandPalette::Search(const std::string& query, int maxResults) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Score and collect
    std::vector<std::pair<double, const CommandItem*>> scored;
    for (const auto& [id, cmd] : m_commands) {
        if (cmd.hidden) continue;

        double score = FuzzyScore(cmd.label + " " + cmd.description + " " + cmd.category, query);

        // Boost exact matches
        if (cmd.label == query) score += 100;
        if (cmd.id == query) score += 50;

        // Boost recent commands
        for (const auto& [recentId, _] : m_recentlyUsed) {
            if (recentId == id) score += 10;
        }

        if (score > 0) {
            scored.push_back({score, &cmd});
        }
    }

    // Sort by score descending
    std::sort(scored.begin(), scored.end(),
        [](const auto& a, const auto& b) { return a.first > b.first; });

    // Return top results
    std::vector<const CommandItem*> results;
    for (size_t i = 0; i < std::min(static_cast<size_t>(maxResults), scored.size()); i++) {
        results.push_back(scored[i].second);
    }

    return results;
}

const CommandItem* CommandPalette::GetCommand(const std::string& id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_commands.find(id);
    return it != m_commands.end() ? &it->second : nullptr;
}

std::vector<const CommandItem*> CommandPalette::ListCommands() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<const CommandItem*> result;
    for (const auto& [id, cmd] : m_commands) {
        result.push_back(&cmd);
    }
    return result;
}

std::vector<const CommandItem*> CommandPalette::ListByCategory(const std::string& category) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<const CommandItem*> result;
    for (const auto& [id, cmd] : m_commands) {
        if (cmd.category == category) result.push_back(&cmd);
    }
    return result;
}

std::vector<std::string> CommandPalette::GetCategories() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> categories;
    for (const auto& [id, cmd] : m_commands) {
        if (std::find(categories.begin(), categories.end(), cmd.category) == categories.end()) {
            categories.push_back(cmd.category);
        }
    }
    return categories;
}

std::vector<const CommandItem*> CommandPalette::GetRecentCommands(int count) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<const CommandItem*> result;
    int found = 0;
    for (auto it = m_recentlyUsed.rbegin(); it != m_recentlyUsed.rend() && found < count; ++it) {
        auto cmdIt = m_commands.find(it->first);
        if (cmdIt != m_commands.end()) {
            result.push_back(&cmdIt->second);
            found++;
        }
    }
    return result;
}

void CommandPalette::RecordCommandUse(const std::string& id) {
    // Remove existing entry if present
    m_recentlyUsed.erase(
        std::remove_if(m_recentlyUsed.begin(), m_recentlyUsed.end(),
            [&](const auto& pair) { return pair.first == id; }),
        m_recentlyUsed.end()
    );
    m_recentlyUsed.push_back({id, std::chrono::steady_clock::now()});

    // Keep only last 50
    if (m_recentlyUsed.size() > 50) {
        m_recentlyUsed.erase(m_recentlyUsed.begin());
    }
}

void CommandPalette::Open() {
    if (m_openCallback) m_openCallback();
}

double CommandPalette::FuzzyScore(const std::string& text, const std::string& query) const {
    if (query.empty()) return 0;

    std::string lowerText = text;
    std::string lowerQuery = query;
    std::transform(lowerText.begin(), lowerText.end(), lowerText.begin(), ::tolower);
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);

    // Check if query is a substring
    auto pos = lowerText.find(lowerQuery);
    if (pos != std::string::npos) {
        // Score based on position (earlier = better) and length ratio
        double lengthRatio = static_cast<double>(query.length()) / text.length();
        double positionScore = 1.0 - (static_cast<double>(pos) / text.length());
        return 50.0 * lengthRatio + 30.0 * positionScore;
    }

    // Fuzzy character-by-character matching
    double score = 0;
    size_t queryIdx = 0;
    size_t lastMatchPos = 0;

    for (size_t i = 0; i < lowerText.size() && queryIdx < lowerQuery.size(); i++) {
        if (lowerText[i] == lowerQuery[queryIdx]) {
            // Bonus for consecutive matches
            if (i == lastMatchPos + 1) score += 5;
            // Bonus for matching at word boundaries
            if (i == 0 || lowerText[i-1] == ' ' || lowerText[i-1] == '_' || lowerText[i-1] == '-') score += 10;
            // Bonus for matching uppercase (camelCase)
            if (i > 0 && isupper(text[i]) && islower(text[i-1])) score += 8;

            score += 3;
            lastMatchPos = i;
            queryIdx++;
        }
    }

    // Full match bonus
    if (queryIdx == lowerQuery.size()) {
        score += 20;
    } else {
        score = 0; // Not all characters matched
    }

    return score;
}

void CommandPalette::RegisterBuiltinCommands() {
    // File operations
    {
        CommandItem cmd;
        cmd.id = "file.new";
        cmd.label = "New File";
        cmd.category = "File";
        cmd.keybinding = "Ctrl+N";
        cmd.description = "Create a new empty file";
        cmd.handler = []() { /* TODO: Create new file */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "file.open";
        cmd.label = "Open File...";
        cmd.category = "File";
        cmd.keybinding = "Ctrl+O";
        cmd.description = "Open a file from disk";
        cmd.handler = []() { /* TODO: Open file dialog */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "file.save";
        cmd.label = "Save";
        cmd.category = "File";
        cmd.keybinding = "Ctrl+S";
        cmd.description = "Save the current file";
        cmd.handler = []() { /* TODO: Save file */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "file.saveAll";
        cmd.label = "Save All";
        cmd.category = "File";
        cmd.keybinding = "Ctrl+K S";
        cmd.description = "Save all open files";
        cmd.handler = []() { /* TODO: Save all */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "file.close";
        cmd.label = "Close File";
        cmd.category = "File";
        cmd.keybinding = "Ctrl+W";
        cmd.description = "Close the current file";
        cmd.handler = []() { /* TODO: Close file */ };
        RegisterCommand(cmd);
    }

    // Edit operations
    {
        CommandItem cmd;
        cmd.id = "edit.undo";
        cmd.label = "Undo";
        cmd.category = "Edit";
        cmd.keybinding = "Ctrl+Z";
        cmd.description = "Undo last action";
        cmd.handler = []() { /* TODO: Undo */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "edit.redo";
        cmd.label = "Redo";
        cmd.category = "Edit";
        cmd.keybinding = "Ctrl+Y";
        cmd.description = "Redo last undone action";
        cmd.handler = []() { /* TODO: Redo */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "edit.cut";
        cmd.label = "Cut";
        cmd.category = "Edit";
        cmd.keybinding = "Ctrl+X";
        cmd.description = "Cut selection to clipboard";
        cmd.handler = []() { /* TODO: Cut */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "edit.copy";
        cmd.label = "Copy";
        cmd.category = "Edit";
        cmd.keybinding = "Ctrl+C";
        cmd.description = "Copy selection to clipboard";
        cmd.handler = []() { /* TODO: Copy */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "edit.paste";
        cmd.label = "Paste";
        cmd.category = "Edit";
        cmd.keybinding = "Ctrl+V";
        cmd.description = "Paste from clipboard";
        cmd.handler = []() { /* TODO: Paste */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "edit.find";
        cmd.label = "Find";
        cmd.category = "Edit";
        cmd.keybinding = "Ctrl+F";
        cmd.description = "Find in current file";
        cmd.handler = []() { /* TODO: Find */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "edit.replace";
        cmd.label = "Find and Replace";
        cmd.category = "Edit";
        cmd.keybinding = "Ctrl+H";
        cmd.description = "Find and replace in current file";
        cmd.handler = []() { /* TODO: Replace */ };
        RegisterCommand(cmd);
    }

    // View operations
    {
        CommandItem cmd;
        cmd.id = "view.commandPalette";
        cmd.label = "Show Command Palette";
        cmd.category = "View";
        cmd.keybinding = "Ctrl+Shift+P";
        cmd.description = "Show the command palette";
        cmd.handler = []() { CommandPalette::Get().Open(); };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "view.explorer";
        cmd.label = "Toggle Explorer";
        cmd.category = "View";
        cmd.keybinding = "Ctrl+Shift+E";
        cmd.description = "Show/hide the file explorer";
        cmd.handler = []() { /* TODO: Toggle explorer */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "view.terminal";
        cmd.label = "Toggle Terminal";
        cmd.category = "View";
        cmd.keybinding = "Ctrl+`";
        cmd.description = "Show/hide the integrated terminal";
        cmd.handler = []() { /* TODO: Toggle terminal */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "view.debug";
        cmd.label = "Toggle Debug Panel";
        cmd.category = "View";
        cmd.keybinding = "Ctrl+Shift+D";
        cmd.description = "Show/hide the debug panel";
        cmd.handler = []() { /* TODO: Toggle debug */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "view.fullscreen";
        cmd.label = "Toggle Full Screen";
        cmd.category = "View";
        cmd.keybinding = "F11";
        cmd.description = "Toggle full screen mode";
        cmd.handler = []() { /* TODO: Toggle fullscreen */ };
        RegisterCommand(cmd);
    }

    // Run operations
    {
        CommandItem cmd;
        cmd.id = "run.build";
        cmd.label = "Run Build Task";
        cmd.category = "Run";
        cmd.keybinding = "Ctrl+Shift+B";
        cmd.description = "Run the default build task";
        cmd.handler = []() { /* TODO: Run build */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "run.test";
        cmd.label = "Run Test Task";
        cmd.category = "Run";
        cmd.keybinding = "Ctrl+Shift+T";
        cmd.description = "Run the default test task";
        cmd.handler = []() { /* TODO: Run test */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "run.debug";
        cmd.label = "Start Debugging";
        cmd.category = "Run";
        cmd.keybinding = "F5";
        cmd.description = "Start debugging the current program";
        cmd.handler = []() { /* TODO: Start debug */ };
        RegisterCommand(cmd);
    }

    // Terminal operations
    {
        CommandItem cmd;
        cmd.id = "terminal.new";
        cmd.label = "New Terminal";
        cmd.category = "Terminal";
        cmd.keybinding = "Ctrl+Shift+`";
        cmd.description = "Create a new integrated terminal";
        cmd.handler = []() { /* TODO: New terminal */ };
        RegisterCommand(cmd);
    }

    // Help operations
    {
        CommandItem cmd;
        cmd.id = "help.about";
        cmd.label = "About RawrXD";
        cmd.category = "Help";
        cmd.description = "Show information about RawrXD";
        cmd.handler = []() { /* TODO: About dialog */ };
        RegisterCommand(cmd);
    }
    {
        CommandItem cmd;
        cmd.id = "help.keyboardShortcuts";
        cmd.label = "Keyboard Shortcuts";
        cmd.category = "Help";
        cmd.keybinding = "Ctrl+K Ctrl+S";
        cmd.description = "Show keyboard shortcut reference";
        cmd.handler = []() { /* TODO: Show shortcuts */ };
        RegisterCommand(cmd);
    }
}

} // namespace UX
} // namespace RawrXD
