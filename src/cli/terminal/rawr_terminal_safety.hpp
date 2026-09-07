// rawr_terminal_safety.hpp — network/destructive default deny
#pragma once
#include <cstring>
#include <string>

namespace rawr::term {

struct TermSafety {
    bool allowNetwork = false;
    bool allowDestructive = false;
    bool approved = false;
};

inline bool IsNetworkCmd(const std::string& c) {
    return c.find("http://") != std::string::npos ||
           c.find("https://") != std::string::npos ||
           c.find("curl ") != std::string::npos ||
           c.find("wget ") != std::string::npos ||
           c.find("Invoke-WebRequest") != std::string::npos;
}

inline bool IsDestructiveCmd(const std::string& c) {
    return c.find("git push") != std::string::npos ||
           c.find("rm -rf") != std::string::npos ||
           c.find("del /s") != std::string::npos ||
           c.find("Remove-Item -Recurse") != std::string::npos ||
           c.find("format ") != std::string::npos ||
           c.find("Wipe") != std::string::npos;
}

inline int GuardCommand(const TermSafety& s, const std::string& cmd) {
    if (IsNetworkCmd(cmd) && !s.allowNetwork && !s.approved) return 51;
    if (IsDestructiveCmd(cmd) && !s.allowDestructive && !s.approved) return 52;
    return 0;
}

} // namespace rawr::term
