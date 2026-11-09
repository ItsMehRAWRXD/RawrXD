#include "AgentProduct.hpp"
#include "AgentSession.hpp"
#include "IdeAuthBoundary.hpp"
#include <windows.h>
#include <fstream>
#include <sstream>

static std::string Arg(const std::string& json, const char* key) {
    const std::string pat = std::string("\"") + key + "\"";
    auto p = json.find(pat);
    if (p == std::string::npos) return {};
    p = json.find(':', p);
    auto a = p == std::string::npos ? std::string::npos : json.find('"', p + 1);
    auto b = a == std::string::npos ? std::string::npos : json.find('"', a + 1);
    if (a == std::string::npos || b == std::string::npos) return {};
    return json.substr(a + 1, b - a - 1);
}

static std::string Esc(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(static_cast<char>(c)); }
        else if (c == '\n') o += "\\n";
        else if (c >= 32) o.push_back(static_cast<char>(c));
        if (o.size() > 4000) break;
    }
    return o;
}

static void ScanDir(const std::string& dir, const std::string& query, std::string& hits, int& n, int depth) {
    if (depth > 4 || n >= 30) return;
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.') continue;
        std::string child = dir + "\\" + fd.cFileName;
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            if (std::string(fd.cFileName) != "node_modules")
                ScanDir(child, query, hits, n, depth + 1);
            continue;
        }
        bool hit = query.empty() || std::string(fd.cFileName).find(query) != std::string::npos;
        if (!hit && !query.empty()) {
            std::ifstream in(child);
            std::string line;
            for (int ln = 0; ln < 400 && std::getline(in, line); ++ln)
                if (line.find(query) != std::string::npos) { hit = true; break; }
        }
        if (hit) {
            for (char& c : child) if (c == '\\') c = '/';
            if (n++) hits += ",";
            hits += "\"" + child + "\"";
        }
    } while (FindNextFileA(h, &fd) && n < 30);
    FindClose(h);
}

std::string AgentExecTool(const std::string& name, const std::string& arguments,
                          std::string* workerId) {
    if (workerId) workerId->clear();
    if (name == "run_subagent") return AgentSpawnWorker(arguments, workerId);
    if (name == "execute_command" || name == "git_status")
        return AgentRunCommand(name, arguments);
    std::string path = Arg(arguments, "path");
    std::string full, err;
    if (name == "search_files" || name == "grep_files" || name == "list_directory") {
        std::string query = Arg(arguments, "query");
        if (query.empty()) query = Arg(arguments, "pattern");
        if (!RawrXD::IdeAuth::CanonicalInsideWorkspace(path.empty() ? "." : path, full, err))
            return "{\"error\":\"" + err + "\"}";
        std::string hits;
        int n = 0;
        ScanDir(full, query, hits, n, 0);
        return "{\"matches\":[" + hits + "]}";
    }
    if (!RawrXD::IdeAuth::CanonicalInsideWorkspace(path, full, err))
        return "{\"error\":\"" + err + "\"}";
    if (name == "read_file") {
        std::ifstream in(full, std::ios::binary);
        std::ostringstream ss; ss << in.rdbuf();
        return "{\"path\":\"" + Esc(full) + "\",\"content\":\"" + Esc(ss.str()) + "\"}";
    }
    if (name == "write_file") {
        std::string previous;
        {
            std::ifstream prior(full, std::ios::binary);
            std::ostringstream prev; prev << prior.rdbuf();
            previous = prev.str();
        }
        std::string content = Arg(arguments, "content");
        std::ofstream out(full, std::ios::binary);
        out << content;
        if (out) AgentSessionNoteWrite(full, previous, content);
        return out ? "{\"wrote\":\"" + Esc(full) + "\"}" : "{\"error\":\"write_failed\"}";
    }
    return "{\"error\":\"unknown_tool\",\"name\":\"" + name + "\"}";
}
