// ============================================================================
// HeadlessIDE_ToolRoutes.cpp — Unstub /api/tool + sibling file/command routes
// ============================================================================
// Reverses public_command_and_file_routes_disabled (403) for local HeadlessIDE E2E.
// Keeps MOTD gate + path traversal fail-closed. Does NOT reintroduce Ollama.
// ============================================================================

#include "HeadlessIDE.h"

#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::atomic<bool> g_headlessMotdAcked{false};
constexpr const char* kMotdNeedle = "PassiveRoleNotRoleplay.md";

std::string motdNormKey(std::string path) {
    for (auto& ch : path)
        if (ch == '/') ch = '\\';
    char full[MAX_PATH * 4] = {};
    DWORD n = GetFullPathNameA(path.c_str(), static_cast<DWORD>(sizeof(full)), full, nullptr);
    if (n > 0 && n < sizeof(full)) path.assign(full);
    for (auto& ch : path)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    while (!path.empty() && (path.back() == '\\' || path.back() == '/')) path.pop_back();
    return path;
}

bool motdPathsEquivalent(const std::string& a, const std::string& b) {
    if (a.empty() || b.empty()) return false;
    return motdNormKey(a) == motdNormKey(b);
}

bool motdLeafIsCanonical(const std::string& path) {
    auto slash = path.find_last_of("\\/");
    std::string leaf = (slash == std::string::npos) ? path : path.substr(slash + 1);
    for (auto& ch : leaf)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return leaf == "passiverolenotroleplay.md" || leaf == "passiverolenotroleplay.mdc";
}

bool motdPathMatches(const std::string& path) {
    if (path.empty()) return false;
    return motdLeafIsCanonical(path);
}


void motdResetForNewMessage() {
    g_headlessMotdAcked.store(false, std::memory_order_release);
}

std::string toolJsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += buf;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

std::string jsonGetString(const nlohmann::json& j, const char* key) {
    if (!j.contains(key)) return {};
    if (j[key].is_string()) return j[key].get<std::string>();
    return {};
}

bool pathHasDotDotComponent(const std::string& path) {
    size_t i = 0;
    while (i < path.size()) {
        while (i < path.size() && (path[i] == '\\' || path[i] == '/')) ++i;
        size_t start = i;
        while (i < path.size() && path[i] != '\\' && path[i] != '/') ++i;
        if (i - start == 2 && path[start] == '.' && path[start + 1] == '.') return true;
    }
    return false;
}

bool resolveToolPath(const std::string& input, const std::string& workingDir,
                     std::string& resolved, std::string& errJson) {
    if (input.empty() || input.find('\0') != std::string::npos) {
        errJson = "{\"error\":\"invalid_path\",\"message\":\"empty path\"}";
        return false;
    }
    if (pathHasDotDotComponent(input)) {
        errJson = "{\"error\":\"forbidden\",\"message\":\"Directory traversal not allowed\"}";
        return false;
    }
    std::string candidate = input;
    for (auto& ch : candidate) {
        if (ch == '/') ch = '\\';
    }
    bool absolute = candidate.size() >= 3 && candidate[1] == ':' &&
        (candidate[2] == '\\' || candidate[2] == '/');
    if (!absolute) {
        if (workingDir.empty()) {
            errJson = "{\"error\":\"invalid_path\",\"message\":\"relative path needs workingDir\"}";
            return false;
        }
        candidate = workingDir + "\\" + candidate;
    }
    char full[MAX_PATH * 4] = {};
    DWORD n = GetFullPathNameA(candidate.c_str(), static_cast<DWORD>(sizeof(full)), full, nullptr);
    if (n == 0 || n >= sizeof(full)) {
        errJson = "{\"error\":\"invalid_path\",\"message\":\"GetFullPathName failed\"}";
        return false;
    }
    resolved.assign(full);
    if (pathHasDotDotComponent(resolved)) {
        errJson = "{\"error\":\"forbidden\",\"message\":\"Directory traversal not allowed\"}";
        return false;
    }
    return true;
}

bool resolveMotdPath(const std::string& workingDir, const std::string& pathArg,
                     std::string& resolved, std::string& errJson) {
    /* Empty pathArg: try .md then .mdc (Cursor ships .mdc under g:\~dev). */
    std::vector<std::string> candidates;
    if (pathArg.empty()) {
        candidates.push_back(".cursor\\rules\\PassiveRoleNotRoleplay.md");
        candidates.push_back(".cursor\\rules\\PassiveRoleNotRoleplay.mdc");
    } else {
        candidates.push_back(pathArg);
    }

    auto tryOne = [&](std::string rel) -> bool {
        for (auto& ch : rel) {
            if (ch == '/') ch = '\\';
        }
        const bool absolute = rel.size() >= 3 && rel[1] == ':' &&
            (rel[2] == '\\' || rel[2] == '/');
        if (absolute)
            return resolveToolPath(rel, workingDir, resolved, errJson);

        if (!workingDir.empty()) {
            std::string viaWd;
            std::string ignore;
            if (resolveToolPath(rel, workingDir, viaWd, ignore) &&
                GetFileAttributesA(viaWd.c_str()) != INVALID_FILE_ATTRIBUTES) {
                resolved = viaWd;
                return true;
            }
        }

        std::vector<std::string> roots;
        if (!workingDir.empty()) roots.push_back(workingDir);
        char cwd[MAX_PATH] = {};
        if (GetCurrentDirectoryA(MAX_PATH, cwd) && cwd[0]) roots.push_back(cwd);
        char modulePath[MAX_PATH * 4] = {};
        if (GetModuleFileNameA(nullptr, modulePath, static_cast<DWORD>(sizeof(modulePath)))) {
            std::string dir(modulePath);
            auto slash = dir.find_last_of("\\/");
            if (slash != std::string::npos) dir.resize(slash);
            for (int up = 0; up < 6; ++up) {
                roots.push_back(dir);
                auto parent = dir.find_last_of("\\/");
                if (parent == std::string::npos) break;
                dir.resize(parent);
            }
        }
        for (const auto& root : roots) {
            std::string cand = root + "\\" + rel;
            if (GetFileAttributesA(cand.c_str()) != INVALID_FILE_ATTRIBUTES) {
                char full[MAX_PATH * 4] = {};
                DWORD n = GetFullPathNameA(cand.c_str(),
                    static_cast<DWORD>(sizeof(full)), full, nullptr);
                if (n > 0 && n < sizeof(full)) {
                    resolved.assign(full);
                    return true;
                }
            }
        }
        return false;
    };

    for (const auto& c : candidates) {
        if (tryOne(c)) return true;
    }
    errJson = "{\"error\":\"file_not_found\",\"message\":\"PassiveRoleNotRoleplay.md/.mdc not found "
              "under workingDir/cwd/module parents\"}";
    return false;
}

bool motdIsExactCanonical(const std::string& workingDir, const std::string& resolved) {
    std::string canon, err;
    if (!resolveMotdPath(workingDir, std::string(), canon, err)) return false;
    return motdPathsEquivalent(resolved, canon);
}

bool readFileLimited(const std::string& path, std::string& content, std::string& errJson) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        errJson = "{\"error\":\"file_not_found\",\"message\":\"Cannot open file: " +
            toolJsonEscape(path) + "\",\"win32_error\":" + std::to_string(err) + "}";
        return false;
    }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0 ||
        static_cast<uint64_t>(size.QuadPart) > (10ULL * 1024 * 1024)) {
        CloseHandle(h);
        errJson = "{\"error\":\"file_too_large\",\"message\":\"File exceeds 10MB limit\"}";
        return false;
    }
    content.assign(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    BOOL ok = ReadFile(h, content.empty() ? nullptr : &content[0],
                       static_cast<DWORD>(content.size()), &read, nullptr);
    CloseHandle(h);
    if (!ok) {
        errJson = "{\"error\":\"read_failed\",\"message\":\"Failed to read file content\"}";
        return false;
    }
    content.resize(read);
    return true;
}

bool writeFileLimited(const std::string& path, const std::string& content, std::string& errJson) {
    if (content.size() > (50ULL * 1024 * 1024)) {
        errJson = "{\"error\":\"content_too_large\",\"message\":\"Content exceeds 50MB write limit\"}";
        return false;
    }
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        errJson = "{\"error\":\"write_failed\",\"message\":\"Cannot write: " +
            toolJsonEscape(path) + "\",\"win32_error\":" + std::to_string(err) + "}";
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(h, content.data(), static_cast<DWORD>(content.size()), &written, nullptr);
    CloseHandle(h);
    if (!ok) {
        errJson = "{\"error\":\"write_failed\",\"message\":\"WriteFile failed\"}";
        return false;
    }
    return true;
}

bool listDirectory(const std::string& path, std::string& outJson, std::string& errJson) {
    std::string pattern = path;
    if (!pattern.empty() && pattern.back() != '\\') pattern += "\\";
    pattern += "*";
    WIN32_FIND_DATAA fd = {};
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        errJson = "{\"error\":\"list_failed\",\"message\":\"Cannot list: " +
            toolJsonEscape(path) + "\"}";
        return false;
    }
    std::ostringstream oss;
    oss << "{\"path\":\"" << toolJsonEscape(path) << "\",\"entries\":[";
    bool first = true;
    do {
        if (std::strcmp(fd.cFileName, ".") == 0 || std::strcmp(fd.cFileName, "..") == 0)
            continue;
        if (!first) oss << ",";
        first = false;
        bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        oss << "{\"name\":\"" << toolJsonEscape(fd.cFileName) << "\",\"type\":\""
            << (isDir ? "dir" : "file") << "\"}";
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    oss << "]}";
    outJson = oss.str();
    return true;
}

bool runLocalCommand(const std::string& command, const std::string& workingDir,
                     std::string& output, DWORD& exitCode) {
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return false;
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi = {};
    std::string cmdline = "cmd.exe /c " + command;
    std::vector<char> mutableCmd(cmdline.begin(), cmdline.end());
    mutableCmd.push_back('\0');

    BOOL ok = CreateProcessA(
        nullptr, mutableCmd.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr,
        workingDir.empty() ? nullptr : workingDir.c_str(),
        &si, &pi);
    CloseHandle(writePipe);
    if (!ok) {
        CloseHandle(readPipe);
        return false;
    }

    char buf[4096];
    DWORD n = 0;
    while (ReadFile(readPipe, buf, sizeof(buf), &n, nullptr) && n > 0) {
        output.append(buf, n);
        if (output.size() > (2ULL * 1024 * 1024)) break;
    }
    CloseHandle(readPipe);
    WaitForSingleObject(pi.hProcess, 30000);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

std::string fileNameOf(const std::string& path) {
    auto slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

} // namespace

void HeadlessIDE::motdResetOnGenerate() {
    motdResetForNewMessage();
}

void HeadlessIDE::routeToolAndFileRequest(const HostedHttpRequest& request,
                                          HostedHttpResponse& response) {
    const std::string& path = request.path;
    if (request.method != "POST") {
        response.status = 405;
        response.body = "{\"error\":\"method_not_allowed\"}";
        return;
    }

    nlohmann::json body = nlohmann::json::object();
    if (!request.body.empty()) {
        try {
            body = nlohmann::json::parse(request.body);
        } catch (...) {
            response.status = 400;
            response.body = "{\"error\":\"invalid_json\"}";
            return;
        }
    }

    std::string tool;
    nlohmann::json args = nlohmann::json::object();

    if (path == "/api/tool" || path == "/run-tool" || path.find("/api/tool/") == 0) {
        tool = jsonGetString(body, "tool");
        if (body.contains("args") && body["args"].is_object()) args = body["args"];
    } else if (path == "/api/read-file" || path == "/api/file/read" || path == "/api/file") {
        tool = "read_file";
        args = body;
    } else if (path == "/api/write-file" || path == "/api/file/write") {
        tool = "write_file";
        args = body;
    } else if (path == "/api/list-dir" || path == "/api/file/list") {
        tool = "list_directory";
        args = body;
    } else if (path == "/api/cli" || path == "/api/command" || path.find("/api/command/") == 0) {
        tool = "execute_command";
        args = body;
    } else if (path == "/api/delete-file") {
        tool = "delete_file";
        args = body;
    } else if (path == "/api/rename-file") {
        tool = "rename_file";
        args = body;
    } else if (path == "/api/copy-file") {
        tool = "copy_file";
        args = body;
    } else if (path == "/api/move-file") {
        tool = "move_file";
        args = body;
    } else if (path == "/api/mkdir") {
        tool = "mkdir";
        args = body;
    } else if (path == "/api/stat-file") {
        tool = "stat_file";
        args = body;
    } else if (path == "/api/search-files") {
        tool = "search_files";
        args = body;
    } else if (path == "/api/list-directory") {
        tool = "list_directory";
        args = body;
    } else if (path.find("/api/file") == 0) {
        response.status = 404;
        response.body = "{\"error\":\"not_found\",\"path\":\"" + toolJsonEscape(path) + "\"}";
        return;
    } else {
        response.status = 404;
        response.body = "{\"error\":\"not_found\",\"path\":\"" + toolJsonEscape(path) + "\"}";
        return;
    }

    if (tool.empty()) {
        response.status = 400;
        response.body =
            "{\"error\":\"missing_tool\",\"message\":\"Request body must contain 'tool' field\"}";
        return;
    }

    std::string out;
    if (!executeToolRepl(tool, args.dump(), out)) {
        // executeToolRepl embeds status in out via side channel? Use parse of error shape.
        // Prefer: executeToolRepl always fills out; return false means hard fail.
        if (out.find("\"error\":\"motd_required\"") != std::string::npos) {
            response.status = 403;
        } else if (out.find("\"error\":\"forbidden\"") != std::string::npos) {
            response.status = 403;
        } else if (out.find("\"error\":\"file_not_found\"") != std::string::npos) {
            response.status = 404;
        } else if (out.find("\"error\":\"unknown_tool\"") != std::string::npos ||
                   out.find("\"error\":\"missing_") != std::string::npos ||
                   out.find("\"error\":\"invalid_path\"") != std::string::npos) {
            response.status = 400;
        } else if (out.find("\"error\":\"file_too_large\"") != std::string::npos ||
                   out.find("\"error\":\"content_too_large\"") != std::string::npos) {
            response.status = 413;
        } else {
            response.status = 500;
        }
        response.body = out.empty() ? "{\"error\":\"tool_failed\"}" : out;
        return;
    }
    response.status = 200;
    response.body = out;
}

bool HeadlessIDE::executeToolRepl(const std::string& toolName,
                                  const std::string& argsJson,
                                  std::string& outResult) {
    nlohmann::json args = nlohmann::json::object();
    if (!argsJson.empty()) {
        try {
            args = nlohmann::json::parse(argsJson);
        } catch (...) {
            outResult = "{\"error\":\"invalid_json\",\"message\":\"args must be JSON object\"}";
            return false;
        }
    }

    const std::string pathArg = jsonGetString(args, "path");
    const bool isMotdRead =
        (toolName == "read_motd") || (toolName == "read_file" && motdPathMatches(pathArg));

    if (!g_headlessMotdAcked.load(std::memory_order_acquire) && !isMotdRead) {
        outResult =
            "{\"error\":\"motd_required\",\"message\":\"Read Message of the Day "
            "(PassiveRoleNotRoleplay.md) via read_file/read_motd before any other tool\"}";
        return false;
    }

    std::string err;
    if (toolName == "read_motd" || toolName == "read_file") {
        std::string resolved;
        bool okPath = false;
        // MOTD reads (empty/relative/abs) resolve via repo/cwd/module roots —
        // do not require --dir for PassiveRoleNotRoleplay parity with Cursor.
        if (toolName == "read_motd" || motdPathMatches(pathArg)) {
            okPath = resolveMotdPath(m_config.workingDir, pathArg, resolved, err);
        } else {
            okPath = resolveToolPath(pathArg, m_config.workingDir, resolved, err);
        }
        if (!okPath) {
            outResult = err;
            return false;
        }
        std::string content;
        if (!readFileLimited(resolved, content, err)) {
            outResult = err;
            return false;
        }
        if (motdIsExactCanonical(m_config.workingDir, resolved))
            g_headlessMotdAcked.store(true, std::memory_order_release);
        outResult = "{\"content\":\"" + toolJsonEscape(content) +
            "\",\"name\":\"" + toolJsonEscape(fileNameOf(resolved)) +
            "\",\"size\":" + std::to_string(content.size()) +
            ",\"path\":\"" + toolJsonEscape(resolved) +
            "\",\"tool\":\"" + toolJsonEscape(toolName) + "\"}";
        return true;
    }

    if (toolName == "write_file") {
        std::string resolved;
        if (!resolveToolPath(pathArg, m_config.workingDir, resolved, err)) {
            outResult = err;
            return false;
        }
        std::string content = jsonGetString(args, "content");
        if (!writeFileLimited(resolved, content, err)) {
            outResult = err;
            return false;
        }
        outResult = "{\"success\":true,\"path\":\"" + toolJsonEscape(resolved) +
            "\",\"name\":\"" + toolJsonEscape(fileNameOf(resolved)) +
            "\",\"size\":" + std::to_string(content.size()) +
            ",\"message\":\"File written successfully\"}";
        return true;
    }

    if (toolName == "list_directory") {
        std::string dir = pathArg.empty() ? m_config.workingDir : pathArg;
        std::string resolved;
        if (!resolveToolPath(dir, m_config.workingDir, resolved, err)) {
            outResult = err;
            return false;
        }
        std::string listed;
        if (!listDirectory(resolved, listed, err)) {
            outResult = err;
            return false;
        }
        outResult = listed;
        return true;
    }

    if (toolName == "execute_command" || toolName == "git_status") {
        std::string command = (toolName == "git_status")
            ? "git status"
            : jsonGetString(args, "command");
        if (command.empty()) {
            outResult = "{\"success\":false,\"error\":\"Missing 'command' field\"}";
            return false;
        }
        std::string output;
        DWORD exitCode = 1;
        if (!runLocalCommand(command, m_config.workingDir, output, exitCode)) {
            outResult = "{\"success\":false,\"error\":\"CreateProcess failed\",\"command\":\"" +
                toolJsonEscape(command) + "\"}";
            return false;
        }
        // HTTP 200 even when exitCode != 0 — tool ran; payload carries success/exitCode.
        outResult = "{\"success\":" + std::string(exitCode == 0 ? "true" : "false") +
            ",\"command\":\"" + toolJsonEscape(command) +
            "\",\"exitCode\":" + std::to_string(exitCode) +
            ",\"output\":\"" + toolJsonEscape(output) + "\"}";
        return true;
    }

    // R04 — delete/rename/copy/move/mkdir/stat/search aliases
    if (toolName == "delete_file" || toolName == "rename_file" || toolName == "copy_file" ||
        toolName == "move_file" || toolName == "mkdir" || toolName == "stat_file" ||
        toolName == "search_files") {
        return executeFileAliasTool(toolName, args, outResult);
    }

    outResult =
        "{\"error\":\"unknown_tool\",\"message\":\"Unknown tool: " + toolJsonEscape(toolName) +
        "\",\"available\":[\"read_motd\",\"read_file\",\"write_file\",\"list_directory\","
        "\"execute_command\",\"git_status\",\"delete_file\",\"rename_file\",\"copy_file\","
        "\"move_file\",\"mkdir\",\"stat_file\",\"search_files\"]}";
    return false;
}
