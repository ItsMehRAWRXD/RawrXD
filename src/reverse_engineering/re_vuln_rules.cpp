// =============================================================================
// re_vuln_rules.cpp — R3 dangerous-API rules over binary content.
// =============================================================================
#include "re_vuln_rules.h"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <vector>

namespace rawrxd::re {

namespace {

struct ApiRule {
    const char* api;
    const char* cwe;
    const char* message;
};

// Dangerous APIs: unbounded or shell/injection-prone. Names are matched as
// whole ASCII tokens inside the binary (import tables keep them verbatim).
const ApiRule kRules[] = {
    {"strcpy", "CWE-120", "unbounded strcpy import"},
    {"strcat", "CWE-120", "unbounded strcat import"},
    {"sprintf", "CWE-120", "unbounded sprintf import"},
    {"gets", "CWE-242", "gets import (removed in C11)"},
    {"scanf", "CWE-120", "scanf import (unbounded %s)"},
    {"system", "CWE-78", "system() import (shell)"},
    {"popen", "CWE-78", "popen() import (shell)"},
    {"WinExec", "CWE-78", "WinExec import (shell)"},
    {"ShellExecute", "CWE-78", "ShellExecute import"},
    {"VirtualAlloc", "CWE-787", "VirtualAlloc (executable memory)"},
    {"WriteProcessMemory", "CWE-400", "WriteProcessMemory (process injection)"},
    {"CreateRemoteThread", "CWE-400", "CreateRemoteThread (injection)"},
    {"LoadLibrary", "CWE-114", "LoadLibrary (DLL search order)"},
    {"SetWindowsHookEx", "CWE-400", "SetWindowsHookEx (hooking)"},
    {"memcpy", "CWE-120", "memcpy import (verify explicit bounds)"},
};

std::string JsonEscape(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
                else out += (char)c;
        }
    }
    return out;
}

}  // namespace

std::vector<VulnFinding> ReVulnScanner::Scan(const std::string& path,
                                             int max_findings) const {
    std::vector<VulnFinding> out;
    std::ifstream in(path, std::ios::binary);
    if (!in) return out;
    std::vector<char> b((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    if (b.empty() || b.size() > 64 * 1024 * 1024) return out;

    for (const auto& rule : kRules) {
        const size_t n = std::strlen(rule.api);
        // Token boundary check: preceding and following chars are not
        // identifier characters (avoids matching e.g. "systematic").
        for (size_t i = 0; i + n <= b.size() && (int)out.size() < max_findings;
             ++i) {
            if (std::memcmp(b.data() + i, rule.api, n) != 0) continue;
            const bool leftOk = (i == 0) ||
                !std::isalnum((unsigned char)b[i - 1]);
            const bool rightOk = (i + n == b.size()) ||
                !std::isalnum((unsigned char)b[i + n]);
            if (!leftOk || !rightOk) continue;
            VulnFinding f;
            f.api = rule.api;
            f.cwe = rule.cwe;
            f.message = rule.message;
            f.offset = (uint64_t)i;
            out.push_back(std::move(f));
            break;  // one finding per API is enough
        }
    }
    return out;
}

std::string ReVulnScanner::ToJson(const std::vector<VulnFinding>& findings) {
    std::ostringstream out;
    out << "[\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        out << "{\"api\":\"" << JsonEscape(f.api) << "\",\"cwe\":\""
            << JsonEscape(f.cwe) << "\",\"offset\":" << f.offset
            << ",\"message\":\"" << JsonEscape(f.message) << "\"}";
        if (i + 1 < findings.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
    return out.str();
}

}  // namespace rawrxd::re