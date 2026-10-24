#pragma once

#include <string>
#include <vector>
#include <functional>
#include <unordered_map>

// IDE_HOOKS - customizable hook system for the RawrXD Agentic IDE.
//
// Hooks are defined in a hook configuration file (default: IDE_HOOKS.md in
// the workspace root). Each hook event can have one or more commands that
// are executed when the event fires. This mirrors the AGENTS.md / MOTD
// pattern: a single text file that users can edit to customize IDE behavior
// without recompiling.
//
// Example IDE_HOOKS.md:
//
//     [hook:startup]
//     echo "IDE starting..."
//
//     [hook:file_open]
//     echo "Opened: {path}"
//
//     [hook:file_save]
//     echo "Saved: {path}"
//
//     [hook:build_start]
//     cmake --build . --config Release
//
//     [hook:shutdown]
//     echo "IDE shutting down..."
//
// Placeholders:
//   {path} - full path of the file being opened/saved
//   {name} - file name only
//   {dir}  - directory of the file

namespace RawrXD {
namespace IdeHooks {

enum class HookEvent {
    Startup,      // IDE window created and ready
    FileOpen,     // user opened a file
    FileSave,     // user saved a file
    BuildStart,   // agent/build command started
    BuildEnd,     // agent/build command finished
    Shutdown,     // IDE window destroyed
};

struct HookEntry {
    HookEvent event;
    std::string command;   // command line to execute
    bool enabled = true;
};

class HookSystem {
public:
    HookSystem() = default;

    // Load hooks from a markdown file. Returns number of hooks loaded.
    int loadFromFile(const std::string& path);

    // Execute all hooks for a given event.
    void fire(HookEvent event, const std::string& placeholderPath = "");

    // Clear all registered hooks.
    void clear();

    // Number of hooks currently loaded.
    size_t count() const { return m_hooks.size(); }

private:
    std::vector<HookEntry> m_hooks;

    // Replace {path}, {name}, {dir} placeholders in a command string.
    std::string expandPlaceholders(const std::string& cmd,
                                   const std::string& path) const;

    // Execute a command string (system() with output captured to status).
    int runCommand(const std::string& cmd) const;
};

} // namespace IdeHooks
} // namespace RawrXD