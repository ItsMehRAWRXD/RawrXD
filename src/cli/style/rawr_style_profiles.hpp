// rawr_style_profiles.hpp — ChatGPT / Codex / Cursor prompt profiles
#pragma once
#include <cstring>
#include <string>

namespace rawr::style {

enum class StyleProfile : int { ChatGPT = 0, Codex = 1, Cursor = 2 };

inline StyleProfile ParseStyleProfile(const char* s) {
    if (!s) return StyleProfile::Cursor;
    if (!_stricmp(s, "chatgpt")) return StyleProfile::ChatGPT;
    if (!_stricmp(s, "codex")) return StyleProfile::Codex;
    return StyleProfile::Cursor;
}

inline const char* StyleProfileName(StyleProfile p) {
    switch (p) {
    case StyleProfile::ChatGPT: return "chatgpt";
    case StyleProfile::Codex: return "codex";
    default: return "cursor";
    }
}

inline std::string StyleSystemPrompt(StyleProfile p) {
    switch (p) {
    case StyleProfile::ChatGPT:
        return "You are a helpful assistant. Answer clearly and completely.";
    case StyleProfile::Codex:
        return "You are a coding agent. Prefer concrete patches, tests, and "
               "commands. Stay inside the workspace.";
    default:
        return "You are a Cursor-style workspace agent. Use tools, terminals, "
               "and patches. Prefer evidence over speculation.";
    }
}

inline bool StyleWantsTools(StyleProfile p) {
    return p == StyleProfile::Codex || p == StyleProfile::Cursor;
}
inline bool StyleWantsPlan(StyleProfile p) {
    return p == StyleProfile::Cursor || p == StyleProfile::Codex;
}

} // namespace rawr::style
