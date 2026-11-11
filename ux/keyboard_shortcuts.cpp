// keyboard_shortcuts.cpp — Keyboard Shortcut Implementation
#include "keyboard_shortcuts.hpp"
#include <fstream>
#include <algorithm>
#include <regex>

namespace RawrXD {
namespace UX {

KeyboardShortcutManager& KeyboardShortcutManager::Get() {
    static KeyboardShortcutManager instance;
    return instance;
}

void KeyboardShortcutManager::RegisterShortcut(const ShortcutEntry& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_shortcuts[entry.key] = entry;
    m_commandToKeys[entry.commandId].push_back(entry.key);
}

void KeyboardShortcutManager::UnregisterShortcut(const KeyDefinition& key) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_shortcuts.find(key);
    if (it != m_shortcuts.end()) {
        auto& keys = m_commandToKeys[it->second.commandId];
        keys.erase(std::remove(keys.begin(), keys.end(), key), keys.end());
        if (keys.empty()) m_commandToKeys.erase(it->second.commandId);
        m_shortcuts.erase(it);
    }
}

std::string KeyboardShortcutManager::GetCommandForKey(const KeyDefinition& key, const std::string& context) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Check chord first
    if (m_chordInProgress) {
        // Look for chord completion
        KeyDefinition chordKey = m_chordFirstKey;
        // TODO: Implement chord matching
        return {};
    }

    auto it = m_shortcuts.find(key);
    if (it == m_shortcuts.end()) return {};

    // Check context condition
    if (!it->second.when.empty() && !context.empty()) {
        // Simple context matching
        if (it->second.when == "editorFocus" && context != "editor") return {};
        if (it->second.when == "terminalFocus" && context != "terminal") return {};
        if (it->second.when == "explorerFocus" && context != "explorer") return {};
    }

    return it->second.commandId;
}

std::vector<KeyDefinition> KeyboardShortcutManager::GetKeysForCommand(const std::string& commandId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_commandToKeys.find(commandId);
    return it != m_commandToKeys.end() ? it->second : std::vector<KeyDefinition>{};
}

bool KeyboardShortcutManager::IsKeyRegistered(const KeyDefinition& key) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_shortcuts.find(key) != m_shortcuts.end();
}

std::vector<ShortcutEntry> KeyboardShortcutManager::ListShortcuts() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ShortcutEntry> result;
    for (const auto& [key, entry] : m_shortcuts) {
        result.push_back(entry);
    }
    return result;
}

std::vector<ShortcutEntry> KeyboardShortcutManager::ListShortcutsByContext(const std::string& context) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ShortcutEntry> result;
    for (const auto& [key, entry] : m_shortcuts) {
        if (entry.when.empty() || entry.when == context) {
            result.push_back(entry);
        }
    }
    return result;
}

bool KeyboardShortcutManager::SetUserShortcut(const std::string& commandId, const KeyDefinition& key) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Check for conflicts
    auto conflictIt = m_shortcuts.find(key);
    if (conflictIt != m_shortcuts.end() && conflictIt->second.commandId != commandId) {
        return false; // Conflict
    }

    ShortcutEntry entry;
    entry.key = key;
    entry.commandId = commandId;
    entry.isUserDefined = true;
    m_shortcuts[key] = entry;
    m_commandToKeys[commandId].push_back(key);
    return true;
}

bool KeyboardShortcutManager::RemoveUserShortcut(const std::string& commandId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_commandToKeys.find(commandId);
    if (it == m_commandToKeys.end()) return false;

    for (const auto& key : it->second) {
        auto shortcutIt = m_shortcuts.find(key);
        if (shortcutIt != m_shortcuts.end() && shortcutIt->second.isUserDefined) {
            m_shortcuts.erase(shortcutIt);
        }
    }
    m_commandToKeys.erase(it);
    return true;
}

void KeyboardShortcutManager::StartChord(const KeyDefinition& firstKey) {
    m_chordInProgress = true;
    m_chordFirstKey = firstKey;
}

void KeyboardShortcutManager::CancelChord() {
    m_chordInProgress = false;
}

bool KeyboardShortcutManager::LoadUserShortcuts(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        auto parseStr = [](const std::string& l, const std::string& key) -> std::string {
            auto pos = l.find("\"" + key + "\"");
            if (pos == std::string::npos) return {};
            auto colon = l.find(':', pos);
            if (colon == std::string::npos) return {};
            auto start = l.find('"', colon + 1);
            if (start == std::string::npos) return {};
            auto end = l.find('"', start + 1);
            if (end == std::string::npos) return {};
            return l.substr(start + 1, end - start - 1);
        };

        if (line.find("\"key\"") != std::string::npos && line.find("\"command\"") != std::string::npos) {
            auto keyStr = parseStr(line, "key");
            auto cmdId = parseStr(line, "command");
            if (!keyStr.empty() && !cmdId.empty()) {
                auto key = ParseKeyString(keyStr);
                SetUserShortcut(cmdId, key);
            }
        }
    }

    return true;
}

bool KeyboardShortcutManager::SaveUserShortcuts(const std::string& filePath) const {
    std::ofstream file(filePath);
    if (!file.is_open()) return false;

    file << "[\n";
    bool first = true;
    for (const auto& [key, entry] : m_shortcuts) {
        if (!entry.isUserDefined) continue;
        if (!first) file << ",\n";
        first = false;
        file << "  {\n";
        file << "    \"key\": \"" << key.ToString() << "\",\n";
        file << "    \"command\": \"" << entry.commandId << "\"\n";
        file << "  }";
    }
    file << "\n]\n";
    return true;
}

std::vector<ShortcutEntry> KeyboardShortcutManager::FindConflicts(const KeyDefinition& key) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ShortcutEntry> conflicts;
    auto it = m_shortcuts.find(key);
    if (it != m_shortcuts.end()) {
        conflicts.push_back(it->second);
    }
    return conflicts;
}

KeyDefinition KeyboardShortcutManager::ParseKeyString(const std::string& keyStr) {
    KeyDefinition key;
    std::string remaining = keyStr;

    // Parse modifiers
    auto parseMod = [&](const std::string& mod) {
        auto pos = remaining.find(mod + "+");
        if (pos != std::string::npos) {
            remaining.erase(pos, mod.length() + 1);
            return true;
        }
        // Try lowercase
        std::string lower = mod;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        pos = remaining.find(lower + "+");
        if (pos != std::string::npos) {
            remaining.erase(pos, lower.length() + 1);
            return true;
        }
        return false;
    };

    if (parseMod("Ctrl")) key.modifiers = key.modifiers | Modifier::Ctrl;
    if (parseMod("Shift")) key.modifiers = key.modifiers | Modifier::Shift;
    if (parseMod("Alt")) key.modifiers = key.modifiers | Modifier::Alt;
    if (parseMod("Win")) key.modifiers = key.modifiers | Modifier::Win;

    key.key = remaining;
    key.displayString = keyStr;

    return key;
}

} // namespace UX
} // namespace RawrXD
