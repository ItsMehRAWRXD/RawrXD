// HeadlessIDE_FileAliases.cpp — R04 thin FS aliases into tool dispatcher
#include "HeadlessIDE.h"
#include <nlohmann/json.hpp>
#include <cstdio>
#include <string>
#include <vector>

namespace {

std::string esc(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '"') o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else o += c;
    }
    return o;
}

std::string jstr(const nlohmann::json& j, const char* a, const char* b = nullptr) {
    if (j.contains(a) && j[a].is_string()) return j[a].get<std::string>();
    if (b && j.contains(b) && j[b].is_string()) return j[b].get<std::string>();
    return {};
}

bool hasDotDot(const std::string& path) {
    size_t i = 0;
    while (i < path.size()) {
        while (i < path.size() && (path[i] == '\\' || path[i] == '/')) ++i;
        size_t start = i;
        while (i < path.size() && path[i] != '\\' && path[i] != '/') ++i;
        if (i - start == 2 && path[start] == '.' && path[start + 1] == '.') return true;
    }
    return false;
}

bool resolvePath(const std::string& workingDir, const std::string& in, std::string& out,
                 std::string& err) {
    if (in.empty() || hasDotDot(in)) {
        err = "{\"error\":\"forbidden\",\"message\":\"invalid path\"}";
        return false;
    }
    std::string cand = in;
    for (auto& ch : cand) if (ch == '/') ch = '\\';
    bool abs = cand.size() >= 3 && cand[1] == ':' && (cand[2] == '\\' || cand[2] == '/');
    if (!abs) {
        if (workingDir.empty()) {
            err = "{\"error\":\"invalid_path\",\"message\":\"relative path needs workingDir\"}";
            return false;
        }
        cand = workingDir + "\\" + cand;
    }
    char full[MAX_PATH * 4] = {};
    DWORD n = GetFullPathNameA(cand.c_str(), static_cast<DWORD>(sizeof(full)), full, nullptr);
    if (!n || n >= sizeof(full) || hasDotDot(full)) {
        err = "{\"error\":\"invalid_path\"}";
        return false;
    }
    out.assign(full);
    return true;
}

void searchRec(const std::string& dir, const std::string& pattern, const std::string& query,
               int maxN, std::string& jsonArr, int& total) {
    std::string glob = dir + "\\*";
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(glob.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.' && (fd.cFileName[1] == 0 ||
            (fd.cFileName[1] == '.' && fd.cFileName[2] == 0))) continue;
        std::string child = dir + "\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            searchRec(child, pattern, query, maxN, jsonArr, total);
        } else {
            bool nameOk = pattern.empty() || pattern == "*" || pattern == "*.*";
            if (!nameOk) {
                std::string leaf = fd.cFileName;
                // crude *.ext match
                if (pattern.size() >= 2 && pattern[0] == '*') {
                    std::string suf = pattern.substr(1);
                    nameOk = leaf.size() >= suf.size() &&
                        _stricmp(leaf.c_str() + leaf.size() - suf.size(), suf.c_str()) == 0;
                }
            }
            if (!nameOk) continue;
            if (!query.empty()) {
                HANDLE hf = CreateFileA(child.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hf == INVALID_HANDLE_VALUE) continue;
                char buf[4096];
                DWORD rd = 0;
                std::string content;
                while (ReadFile(hf, buf, sizeof(buf), &rd, nullptr) && rd) {
                    content.append(buf, rd);
                    if (content.size() > 256 * 1024) break;
                }
                CloseHandle(hf);
                if (content.find(query) == std::string::npos) continue;
            }
            if (total > 0) jsonArr += ",";
            jsonArr += "{\"path\":\"" + esc(child) + "\"}";
            ++total;
            if (total >= maxN) { FindClose(h); return; }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

} // namespace

bool HeadlessIDE::executeFileAliasTool(const std::string& toolName, const nlohmann::json& args,
                                       std::string& outResult) {
    std::string err;
    const std::string& wd = m_config.workingDir;
    if (toolName == "delete_file") {
        std::string path = jstr(args, "path");
        std::string resolved;
        if (!resolvePath(wd, path, resolved, err)) { outResult = err; return false; }
        DWORD attr = GetFileAttributesA(resolved.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            outResult = "{\"error\":\"file_not_found\",\"path\":\"" + esc(resolved) + "\"}";
            return false;
        }
        bool force = args.value("force", false);
        if (force && (attr & FILE_ATTRIBUTE_READONLY))
            SetFileAttributesA(resolved.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
        BOOL ok = (attr & FILE_ATTRIBUTE_DIRECTORY) ? RemoveDirectoryA(resolved.c_str())
                                                    : DeleteFileA(resolved.c_str());
        if (!ok) {
            outResult = "{\"error\":\"delete_failed\",\"win32_error\":" +
                std::to_string(GetLastError()) + "}";
            return false;
        }
        outResult = "{\"success\":true,\"path\":\"" + esc(resolved) +
            "\",\"message\":\"Deleted successfully\"}";
        return true;
    }
    if (toolName == "rename_file") {
        std::string oldP = jstr(args, "path", "old_path");
        std::string newP = jstr(args, "newPath", "new_path");
        std::string a, b;
        if (!resolvePath(wd, oldP, a, err) || !resolvePath(wd, newP, b, err)) {
            outResult = err; return false;
        }
        if (!MoveFileA(a.c_str(), b.c_str())) {
            outResult = "{\"error\":\"rename_failed\",\"win32_error\":" +
                std::to_string(GetLastError()) + "}";
            return false;
        }
        outResult = "{\"success\":true,\"oldPath\":\"" + esc(a) + "\",\"newPath\":\"" +
            esc(b) + "\",\"message\":\"Renamed successfully\"}";
        return true;
    }
    if (toolName == "copy_file") {
        std::string src = jstr(args, "path", "source");
        std::string dst = jstr(args, "destPath", "destination");
        std::string a, b;
        if (!resolvePath(wd, src, a, err) || !resolvePath(wd, dst, b, err)) {
            outResult = err; return false;
        }
        bool overwrite = args.value("overwrite", false);
        if (!CopyFileA(a.c_str(), b.c_str(), overwrite ? FALSE : TRUE)) {
            outResult = "{\"error\":\"copy_failed\",\"win32_error\":" +
                std::to_string(GetLastError()) + "}";
            return false;
        }
        outResult = "{\"success\":true,\"source\":\"" + esc(a) + "\",\"dest\":\"" + esc(b) + "\"}";
        return true;
    }
    if (toolName == "move_file") {
        std::string src = jstr(args, "path", "source");
        std::string dst = jstr(args, "destPath", "destination");
        std::string a, b;
        if (!resolvePath(wd, src, a, err) || !resolvePath(wd, dst, b, err)) {
            outResult = err; return false;
        }
        bool overwrite = args.value("overwrite", false);
        DWORD flags = MOVEFILE_COPY_ALLOWED | (overwrite ? MOVEFILE_REPLACE_EXISTING : 0);
        if (!MoveFileExA(a.c_str(), b.c_str(), flags)) {
            outResult = "{\"error\":\"move_failed\",\"win32_error\":" +
                std::to_string(GetLastError()) + "}";
            return false;
        }
        outResult = "{\"success\":true,\"source\":\"" + esc(a) + "\",\"dest\":\"" + esc(b) + "\"}";
        return true;
    }
    if (toolName == "mkdir") {
        std::string path = jstr(args, "path");
        std::string resolved;
        if (!resolvePath(wd, path, resolved, err)) { outResult = err; return false; }
        // recursive mkdir via SHCreateDirectoryExA-like loop
        for (size_t i = 3; i < resolved.size(); ++i) {
            if (resolved[i] == '\\' || resolved[i] == '/') {
                std::string part = resolved.substr(0, i);
                CreateDirectoryA(part.c_str(), nullptr);
            }
        }
        CreateDirectoryA(resolved.c_str(), nullptr);
        outResult = "{\"success\":true,\"path\":\"" + esc(resolved) +
            "\",\"message\":\"Directory created\"}";
        return true;
    }
    if (toolName == "stat_file") {
        std::string path = jstr(args, "path");
        std::string resolved;
        if (!resolvePath(wd, path, resolved, err)) { outResult = err; return false; }
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (!GetFileAttributesExA(resolved.c_str(), GetFileExInfoStandard, &fad)) {
            outResult = "{\"exists\":false,\"path\":\"" + esc(resolved) + "\"}";
            return true;
        }
        ULARGE_INTEGER sz;
        sz.LowPart = fad.nFileSizeLow;
        sz.HighPart = fad.nFileSizeHigh;
        bool isDir = (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        outResult = "{\"exists\":true,\"path\":\"" + esc(resolved) + "\",\"size\":" +
            std::to_string(sz.QuadPart) + ",\"isDir\":" + (isDir ? "true" : "false") + "}";
        return true;
    }
    if (toolName == "search_files") {
        std::string path = jstr(args, "path");
        if (path.empty()) path = m_config.workingDir;
        std::string resolved;
        if (!resolvePath(wd, path, resolved, err)) { outResult = err; return false; }
        std::string pattern = jstr(args, "pattern");
        std::string query = jstr(args, "query");
        int maxN = args.value("maxResults", 500);
        if (maxN < 1) maxN = 1;
        if (maxN > 10000) maxN = 10000;
        std::string arr;
        int total = 0;
        searchRec(resolved, pattern, query, maxN, arr, total);
        outResult = "{\"results\":[" + arr + "],\"total\":" + std::to_string(total) +
            ",\"searchPath\":\"" + esc(resolved) + "\"}";
        return true;
    }
    return false;
}
