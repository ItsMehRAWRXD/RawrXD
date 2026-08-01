// keyboard_shortcuts.hpp — Keyboard Shortcut System
#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <set>
#include <mutex>
#include <sstream>
#include <cctype>

namespace RawrXD {
namespace UX {

// ============================================================================
// Modifier Keys
// ============================================================================
enum class Modifier : int {
    None    = 0,
    Ctrl    = 1 << 0,
    Shift   = 1 << 1,
    Alt     = 1 << 2,
    Win     = 1 << 3
};

inline Modifier operator|(Modifier a, Modifier b) {
    return static_cast<Modifier>(static_cast<int>(a) | static_cast<int>(b));
}

inline Modifier operator&(Modifier a, Modifier b) {
    return static_cast<Modifier>(static_cast<int>(a) & static_cast<int>(b));
}

// ============================================================================
// Key Definition
// ============================================================================
struct KeyDefinition {
    Modifier modifiers = Modifier::None;
    std::string key;           // "A", "F1", "Space", "Enter", "Escape", etc.
    std::string displayString; // "Ctrl+Shift+P"

    std::string ToString() const {
        if (!displayString.empty()) return displayString;
        std::string result;
        if ((modifiers & Modifier::Ctrl) != Modifier::None) result += "Ctrl+";
        if ((modifiers & Modifier::Shift) != Modifier::None) result += "Shift+";
        if ((modifiers & Modifier::Alt) != Modifier::None) result += "Alt+";
        if ((modifiers & Modifier::Win) != Modifier::None) result += "Win+";
        result += key;
        return result;
    }

    bool operator<(const KeyDefinition& other) const {
        if (static_cast<int>(modifiers) != static_cast<int>(other.modifiers))
            return static_cast<int>(modifiers) < static_cast<int>(other.modifiers);
        return key < other.key;
    }

    bool operator==(const KeyDefinition& other) const {
        return modifiers == other.modifiers && key == other.key;
    }
};

// ============================================================================
// Shortcut Entry
// ============================================================================
struct ShortcutEntry {
    KeyDefinition key;
    std::string commandId;
    std::string when;           // Context condition: "editorFocus", "terminalFocus", etc.
    std::string label;
    bool isBuiltin = false;
    bool isUserDefined = false;
};

// ============================================================================
// Keyboard Shortcut Manager
// ============================================================================
class KeyboardShortcutManager {
public:
    static KeyboardShortcutManager& Get();

    // Register a shortcut
    void RegisterShortcut(const ShortcutEntry& entry);

    // Unregister a shortcut
    void UnregisterShortcut(const KeyDefinition& key);

    // Find command for key combination
    std::string GetCommandForKey(const KeyDefinition& key, const std::string& context = "") const;

    // Find key for command
    std::vector<KeyDefinition> GetKeysForCommand(const std::string& commandId) const;

    // Check if key combination is registered
    bool IsKeyRegistered(const KeyDefinition& key) const;

    // List all shortcuts
    std::vector<ShortcutEntry> ListShortcuts() const;

    // List shortcuts by context
    std::vector<ShortcutEntry> ListShortcutsByContext(const std::string& context) const;

    // User-defined shortcut overrides
    bool SetUserShortcut(const std::string& commandId, const KeyDefinition& key);
    bool RemoveUserShortcut(const std::string& commandId);

    // Detect key chord (two-key sequence like Ctrl+K Ctrl+S)
    bool IsChordInProgress() const { return m_chordInProgress; }
    void StartChord(const KeyDefinition& firstKey);
    void CancelChord();
    KeyDefinition GetChordFirstKey() const { return m_chordFirstKey; }

    // Load/save user shortcuts
    bool LoadUserShortcuts(const std::string& filePath);
    bool SaveUserShortcuts(const std::string& filePath) const;

    // Conflict detection
    std::vector<ShortcutEntry> FindConflicts(const KeyDefinition& key) const;

    // Parse key string like "Ctrl+Shift+P"
    static KeyDefinition ParseKeyString(const std::string& keyStr);

private:
    KeyboardShortcutManager() = default;

    std::map<KeyDefinition, ShortcutEntry> m_shortcuts;
    std::map<std::string, std::vector<KeyDefinition>> m_commandToKeys;
    bool m_chordInProgress = false;
    KeyDefinition m_chordFirstKey;
    mutable std::mutex m_mutex;
};

} // namespace UX
} // namespace RawrXD
