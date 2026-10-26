#include "IdeAuthBoundary.hpp"
#include <windows.h>
#include <string>

namespace RawrXD::IdeAuth {
namespace {
std::string g_root;

std::string Norm(std::string p) {
    for (char& c : p) if (c == '/') c = '\\';
    if (p.rfind("\\\\?\\", 0) == 0) p.erase(0, 4);
    for (char& c : p) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    while (!p.empty() && p.back() == '\\') p.pop_back();
    return p;
}

bool DotDot(const std::string& path) {
    size_t i = 0;
    while (i < path.size()) {
        while (i < path.size() && (path[i] == '\\' || path[i] == '/')) ++i;
        size_t s = i;
        while (i < path.size() && path[i] != '\\' && path[i] != '/') ++i;
        if (i - s == 2 && path[s] == '.' && path[s + 1] == '.') return true;
    }
    return false;
}

bool Under(const std::string& root, const std::string& full) {
    if (root.empty() || full.empty()) return false;
    if (full == root) return true;
    return full.size() > root.size() && full.compare(0, root.size(), root) == 0 &&
           full[root.size()] == '\\';
}

bool FinalPath(const std::string& lexical, std::string& out, std::string& error) {
    HANDLE h = CreateFileA(lexical.c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD gle = GetLastError();
        if (gle != ERROR_FILE_NOT_FOUND && gle != ERROR_PATH_NOT_FOUND) {
            error = "path open failed";
            return false;
        }
        const auto slash = lexical.find_last_of('\\');
        if (slash == std::string::npos) { error = "outside workspace"; return false; }
        const std::string parent = lexical.substr(0, slash);
        if (GetFileAttributesA(parent.c_str()) == INVALID_FILE_ATTRIBUTES) {
            out = lexical;
            return true;
        }
        std::string parentFinal;
        if (!FinalPath(parent, parentFinal, error)) return false;
        out = parentFinal + "\\" + lexical.substr(slash + 1);
        return true;
    }
    char buf[4096] = {};
    DWORD n = GetFinalPathNameByHandleA(h, buf, sizeof(buf), FILE_NAME_NORMALIZED);
    CloseHandle(h);
    if (n == 0 || n >= sizeof(buf)) { error = "final path failed"; return false; }
    out.assign(buf, n);
    return true;
}
}

void SetWorkspaceRoot(const std::string& root) {
    char full[4096] = {};
    DWORD n = GetFullPathNameA(root.c_str(), sizeof(full), full, nullptr);
    g_root = Norm(n ? std::string(full) : root);
}

bool CanonicalInsideWorkspace(const std::string& input, std::string& canonical,
                              std::string& error) {
    if (g_root.empty()) { error = "workspace unset"; return false; }
    if (input.empty() || input.find('\0') != std::string::npos) {
        error = "empty path"; return false;
    }
    if ((input.size() >= 2 && input[0] == '\\' && input[1] == '\\') ||
        (input.size() >= 2 && input[0] == '/' && input[1] == '/')) {
        error = "unc rejected"; return false;
    }
    if (DotDot(input)) { error = "traversal rejected"; return false; }
    std::string cand = input;
    for (char& c : cand) if (c == '/') c = '\\';
    const bool abs = cand.size() >= 3 && cand[1] == ':' && cand[2] == '\\';
    if (!abs) cand = g_root + "\\" + cand;
    char full[4096] = {};
    DWORD n = GetFullPathNameA(cand.c_str(), sizeof(full), full, nullptr);
    if (!n || n >= sizeof(full) || DotDot(full)) {
        error = "invalid path"; return false;
    }
    std::string resolved;
    if (!FinalPath(full, resolved, error)) return false;
    resolved = Norm(resolved);
    if (!Under(g_root, resolved)) { error = "outside workspace"; return false; }
    canonical = resolved;
    return true;
}
}
