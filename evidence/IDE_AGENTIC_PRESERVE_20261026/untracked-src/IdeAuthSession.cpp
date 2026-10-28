#include "IdeAuthBoundary.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#pragma comment(lib, "bcrypt.lib")

namespace RawrXD::IdeAuth {
namespace {
int g_port = 11435;
char g_token[65] = {};
thread_local char g_allowOrigin[160] = {};

bool CtEq(const char* a, const char* b, size_t n) {
    unsigned diff = 0;
    for (size_t i = 0; i < n; ++i)
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return diff == 0;
}

void IssueToken() {
    unsigned char raw[32] = {};
    if (BCryptGenRandom(nullptr, raw, sizeof(raw), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return;
    static const char* hex = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        g_token[i * 2] = hex[raw[i] >> 4];
        g_token[i * 2 + 1] = hex[raw[i] & 0xF];
    }
    g_token[64] = 0;
}
}

std::string HeaderField(const std::string& headers, const char* key) {
    std::string lower = headers;
    for (char& c : lower)
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    std::string needle = key;
    auto pos = lower.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    while (pos < headers.size() && (headers[pos] == ' ' || headers[pos] == '\t')) ++pos;
    auto end = headers.find("\r\n", pos);
    if (end == std::string::npos) end = headers.size();
    return headers.substr(pos, end - pos);
}

void SetListenPort(int port) { if (port > 0 && port < 65536) g_port = port; }
const char* SessionToken() { if (!g_token[0]) IssueToken(); return g_token; }

bool PrivilegedExecGranted() {
    const char* v = std::getenv("RAWRXD_IDE_EXEC_GRANT");
    return v && (v[0] == '1' || _stricmp(v, "true") == 0 || _stricmp(v, "yes") == 0);
}

bool OriginAllowed(const std::string& origin) {
    if (origin.empty()) return true;
    if (origin == "null" || origin == "*") return false;
    const std::string suffix = ":" + std::to_string(g_port);
    return origin == "http://127.0.0.1" + suffix ||
           origin == "http://localhost" + suffix ||
           origin == "http://[::1]" + suffix;
}

bool HeaderHasSession(const std::string& headers) {
    const char* token = SessionToken();
    std::string got = HeaderField(headers, "x-rawrxd-session:");
    if (got.empty()) {
        std::string auth = HeaderField(headers, "authorization:");
        const std::string prefix = "Bearer ";
        if (auth.rfind(prefix, 0) == 0) got = auth.substr(prefix.size());
    }
    return got.size() == 64 && CtEq(got.c_str(), token, 64);
}

void NoteResponseOrigin(const std::string& origin) {
    g_allowOrigin[0] = 0;
    if (origin.empty() || !OriginAllowed(origin)) return;
    strncpy_s(g_allowOrigin, origin.c_str(), _TRUNCATE);
}

const char* ResponseAllowOrigin() { return g_allowOrigin; }

std::string CorsHeaderLines() {
    if (!g_allowOrigin[0]) return {};
    return std::string("Access-Control-Allow-Origin: ") + g_allowOrigin +
           "\r\nVary: Origin\r\n";
}
}
