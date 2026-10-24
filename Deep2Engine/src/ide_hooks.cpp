#include "ide_hooks.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

namespace RawrXD {
namespace IdeHooks {

static const char* kEventNames[] = {
    "startup",
    "file_open",
    "file_save",
    "build_start",
    "build_end",
    "shutdown",
};

static HookEvent parseEventName(const std::string& name) {
    for (int i = 0; i < 6; ++i) {
        if (name == kEventNames[i]) return static_cast<HookEvent>(i);
    }
    return static_cast<HookEvent>(-1);
}

static std::string trim(const std::string& s) {
    auto start = std::find_if_not(s.begin(), s.end(), [](unsigned char c) { return std::isspace(c); });
    auto end = std::find_if_not(s.rbegin(), s.rend(), [](unsigned char c) { return std::isspace(c); }).base();
    return (start < end) ? std::string(start, end) : "";
}

// Read a file into a string.
static std::string readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

std::string HookSystem::expandPlaceholders(const std::string& cmd,
                                           const std::string& path) const {
    std::string result = cmd;
    std::string name = path;
    std::string dir = path;

    auto slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
        name = path.substr(slash + 1);
        dir = path.substr(0, slash);
    }

    // Replace {path}
    size_t pos = 0;
    while ((pos = result.find("{path}", pos)) != std::string::npos) {
        result.replace(pos, 6, path);
        pos += path.size();
    }
    // Replace {name}
    pos = 0;
    while ((pos = result.find("{name}", pos)) != std::string::npos) {
        result.replace(pos, 6, name);
        pos += name.size();
    }
    // Replace {dir}
    pos = 0;
    while ((pos = result.find("{dir}", pos)) != std::string::npos) {
        result.replace(pos, 5, dir);
        pos += dir.size();
    }
    return result;
}

int HookSystem::runCommand(const std::string& cmd) const {
    std::cout << "[HOOK] " << cmd << std::endl;
    return static_cast<int>(std::system(cmd.c_str()));
}

int HookSystem::loadFromFile(const std::string& path) {
    std::string content = readFile(path);
    if (content.empty()) {
        std::cerr << "[HOOK] Hook file not found or empty: " << path << std::endl;
        return 0;
    }

    std::istringstream iss(content);
    std::string line;
    HookEvent currentEvent = static_cast<HookEvent>(-1);
    int loaded = 0;

    while (std::getline(iss, line)) {
        std::string trimmed = trim(line);

        // Skip empty lines and comments
        if (trimmed.empty() || trimmed[0] == '#') continue;

        // Detect [hook:event] section header
        if (trimmed.size() >= 8 && trimmed[0] == '[' && trimmed[1] == 'h' &&
            trimmed[2] == 'o' && trimmed[3] == 'o' && trimmed[4] == 'k' &&
            trimmed[5] == ':' && trimmed.back() == ']') {
            std::string eventName = trim(trimmed.substr(6, trimmed.size() - 7));
            currentEvent = parseEventName(eventName);
            if (currentEvent == static_cast<HookEvent>(-1)) {
                std::cerr << "[HOOK] Unknown hook event: " << eventName << std::endl;
            }
            continue;
        }

        // If we're inside a hook section, add the line as a command
        if (currentEvent != static_cast<HookEvent>(-1) && !trimmed.empty()) {
            HookEntry entry;
            entry.event = currentEvent;
            entry.command = trimmed;
            m_hooks.push_back(entry);
            ++loaded;
        }
    }

    std::cout << "[HOOK] Loaded " << loaded << " hooks from " << path << std::endl;
    return loaded;
}

void HookSystem::fire(HookEvent event, const std::string& placeholderPath) {
    for (const auto& entry : m_hooks) {
        if (entry.event == event && entry.enabled) {
            runCommand(expandPlaceholders(entry.command, placeholderPath));
        }
    }
}

void HookSystem::clear() {
    m_hooks.clear();
}

} // namespace IdeHooks
} // namespace RawrXD