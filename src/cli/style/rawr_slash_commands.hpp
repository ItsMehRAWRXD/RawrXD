// rawr_slash_commands.hpp — /help /model /auto /term /steer /compact ...
#pragma once
#include "rawr_style_profiles.hpp"
#include <string>
#include <vector>

namespace rawr::style {

struct SlashCommand {
    std::string verb;
    std::string arg;
    bool ok = false;
};

inline bool IsSlashLine(const std::string& line) {
    return !line.empty() && line[0] == '/';
}

inline SlashCommand ParseSlash(const std::string& line) {
    SlashCommand c{};
    if (!IsSlashLine(line)) return c;
    auto sp = line.find(' ');
    c.verb = sp == std::string::npos ? line.substr(1) : line.substr(1, sp - 1);
    if (sp != std::string::npos) c.arg = line.substr(sp + 1);
    c.ok = !c.verb.empty();
    return c;
}

inline const char* SlashHelpText() {
    return "/help /model <alias> /auto <level> /profile chatgpt|codex|cursor\n"
           "/term start|tail|stop <name> /steer <cmd> /compact /quit\n";
}

inline bool KnownSlash(const std::string& verb) {
    static const char* k[] = {"help",   "model", "auto",  "profile", "term",
                              "steer",  "compact", "quit", "exit",  "clear",
                              "plan",   "diff",  nullptr};
    for (int i = 0; k[i]; ++i)
        if (!_stricmp(verb.c_str(), k[i])) return true;
    return false;
}

} // namespace rawr::style
