// rawr_terminal_protocol.hpp — local named-pipe line protocol (no network)
#pragma once
#include <string>

namespace rawr::term {

inline const char* HostPipeName() { return "\\\\.\\pipe\\rawrxd_term_host"; }
inline const char* HostMutexName() { return "Local\\rawrxd_term_host_mtx"; }

// Requests (one line, UTF-8):
//   PING
//   START <name> -- <cmdline>
//   TAIL <name> [maxBytes]
//   STATUS <name>
//   LIST
//   SEND <name> -- <text>
//   STOP <name>
//   KILLALL
// Responses:
//   +OK ...
//   +DATA <n>\n <n bytes>
//   -ERR <code> <msg>

inline bool StartsWith(const std::string& s, const char* pfx) {
    size_t n = 0;
    while (pfx[n]) ++n;
    return s.size() >= n && s.compare(0, n, pfx) == 0;
}

inline std::string OkLine(const std::string& rest) { return "+OK " + rest + "\n"; }
inline std::string ErrLine(int code, const std::string& msg) {
    return "-ERR " + std::to_string(code) + " " + msg + "\n";
}

} // namespace rawr::term
