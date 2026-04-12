#include "tool_registry.h"
#include "tool_registry_init.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <sstream>

#include <nlohmann/json.hpp>

static std::unordered_map<std::string, ToolFunc> tools;
static std::mutex tools_mutex;
static std::once_flag tools_once;

namespace {

using json = nlohmann::json;
namespace fs = std::filesystem;

inline std::string WorkspaceRoot() {
    const char* env_root = std::getenv("RAWRXD_TOOL_WORKSPACE");
    if (env_root != nullptr && env_root[0] != 0) {
        return std::string(env_root);
    }
    return fs::current_path().string();
}

inline bool IsPathAllowed(const fs::path& path) {
    try {
        const fs::path canonical_root = fs::weakly_canonical(WorkspaceRoot());
        const fs::path canonical_target = fs::weakly_canonical(path);
        const auto rel = canonical_target.lexically_relative(canonical_root);
        if (rel.empty()) {
            return false;
        }
        const std::string rel_text = rel.generic_string();
        return rel_text.rfind("..", 0) != 0;
    } catch (...) {
        return false;
    }
}

inline std::string JsonEscape(const std::string& value) {
    json j = value;
    return j.dump();
}

inline std::string ReadAllText(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::string();
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

inline bool WriteAllText(const fs::path& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    return out.good();
}

void RegisterCoreTools() {
    ToolRegistry::register_tool("read_file", [](const std::string& input) -> std::string {
        try {
            const json req = json::parse(input.empty() ? "{}" : input);
            const std::string path_raw = req.value("path", "");
            const size_t offset = req.value("offset", static_cast<size_t>(0));
            const size_t limit = req.value("limit", static_cast<size_t>(65536));
            if (path_raw.empty()) {
                return R"({"success":false,"error":"missing path"})";
            }
            fs::path target = fs::path(path_raw);
            if (!target.is_absolute()) {
                target = fs::path(WorkspaceRoot()) / target;
            }
            if (!IsPathAllowed(target)) {
                return R"({"success":false,"error":"access denied"})";
            }
            const std::string text = ReadAllText(target);
            if (text.empty() && !fs::exists(target)) {
                return R"({"success":false,"error":"file not found"})";
            }
            const size_t safe_offset = std::min(offset, text.size());
            const size_t safe_limit = std::min(limit, text.size() - safe_offset);
            const std::string slice = text.substr(safe_offset, safe_limit);
            json resp;
            resp["success"] = true;
            resp["path"] = target.string();
            resp["offset"] = safe_offset;
            resp["bytes"] = slice.size();
            resp["content"] = slice;
            return resp.dump();
        } catch (const std::exception& e) {
            return std::string("{\"success\":false,\"error\":") + JsonEscape(e.what()) + "}";
        }
    });

    ToolRegistry::register_tool("edit_file", [](const std::string& input) -> std::string {
        try {
            const json req = json::parse(input.empty() ? "{}" : input);
            const std::string path_raw = req.value("path", "");
            const std::string old_s = req.value("old_string", "");
            const std::string new_s = req.value("new_string", "");
            if (path_raw.empty()) {
                return R"({"success":false,"error":"missing path"})";
            }
            fs::path target = fs::path(path_raw);
            if (!target.is_absolute()) {
                target = fs::path(WorkspaceRoot()) / target;
            }
            if (!IsPathAllowed(target)) {
                return R"({"success":false,"error":"access denied"})";
            }
            std::string text = ReadAllText(target);
            if (text.empty() && !fs::exists(target)) {
                return R"({"success":false,"error":"file not found"})";
            }
            size_t replaced = 0;
            if (!old_s.empty()) {
                size_t pos = 0;
                while ((pos = text.find(old_s, pos)) != std::string::npos) {
                    text.replace(pos, old_s.size(), new_s);
                    pos += new_s.size();
                    ++replaced;
                }
            }
            if (!WriteAllText(target, text)) {
                return R"({"success":false,"error":"write failed"})";
            }
            json resp;
            resp["success"] = true;
            resp["path"] = target.string();
            resp["replacements"] = replaced;
            return resp.dump();
        } catch (const std::exception& e) {
            return std::string("{\"success\":false,\"error\":") + JsonEscape(e.what()) + "}";
        }
    });

    ToolRegistry::register_tool("run_terminal", [](const std::string& input) -> std::string {
        try {
            const json req = json::parse(input.empty() ? "{}" : input);
            const std::string command = req.value("command", "");
            if (command.empty()) {
                return R"({"success":false,"error":"missing command"})";
            }
            if (command.find("rm -rf") != std::string::npos || command.find("del /f") != std::string::npos ||
                command.find("format ") != std::string::npos) {
                return R"({"success":false,"error":"command blocked by policy"})";
            }
            FILE* pipe = _popen(command.c_str(), "r");
            if (pipe == nullptr) {
                return R"({"success":false,"error":"process spawn failed"})";
            }
            std::string out;
            char buf[512];
            while (std::fgets(buf, static_cast<int>(sizeof(buf)), pipe) != nullptr) {
                out.append(buf);
            }
            const int rc = _pclose(pipe);
            json resp;
            resp["success"] = (rc == 0);
            resp["exit_code"] = rc;
            resp["output"] = out;
            return resp.dump();
        } catch (const std::exception& e) {
            return std::string("{\"success\":false,\"error\":") + JsonEscape(e.what()) + "}";
        }
    });

    ToolRegistry::register_tool("search_code", [](const std::string& input) -> std::string {
        try {
            const json req = json::parse(input.empty() ? "{}" : input);
            const std::string query = req.value("query", "");
            const std::string path_raw = req.value("path", WorkspaceRoot());
            const bool regex = req.value("regex", false);
            if (query.empty()) {
                return R"({"success":false,"error":"missing query"})";
            }
            fs::path root(path_raw);
            if (!root.is_absolute()) {
                root = fs::path(WorkspaceRoot()) / root;
            }
            if (!IsPathAllowed(root)) {
                return R"({"success":false,"error":"access denied"})";
            }
            json hits = json::array();
            std::regex rx;
            if (regex) {
                rx = std::regex(query, std::regex::ECMAScript | std::regex::icase);
            }
            size_t hit_cap = 200;
            for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied);
                 it != fs::recursive_directory_iterator() && hits.size() < hit_cap; ++it) {
                if (!it->is_regular_file()) {
                    continue;
                }
                const auto ext = it->path().extension().string();
                if (ext != ".cpp" && ext != ".h" && ext != ".hpp" && ext != ".c" && ext != ".asm") {
                    continue;
                }
                const std::string text = ReadAllText(it->path());
                if (text.empty()) {
                    continue;
                }
                bool matched = false;
                if (regex) {
                    matched = std::regex_search(text, rx);
                } else {
                    matched = text.find(query) != std::string::npos;
                }
                if (matched) {
                    json h;
                    h["path"] = it->path().string();
                    hits.push_back(h);
                }
            }
            json resp;
            resp["success"] = true;
            resp["count"] = hits.size();
            resp["hits"] = hits;
            return resp.dump();
        } catch (const std::exception& e) {
            return std::string("{\"success\":false,\"error\":") + JsonEscape(e.what()) + "}";
        }
    });

    ToolRegistry::register_tool("list_dir", [](const std::string& input) -> std::string {
        try {
            const json req = json::parse(input.empty() ? "{}" : input);
            const std::string path_raw = req.value("path", WorkspaceRoot());
            const bool recursive = req.value("recursive", false);
            fs::path root(path_raw);
            if (!root.is_absolute()) {
                root = fs::path(WorkspaceRoot()) / root;
            }
            if (!IsPathAllowed(root)) {
                return R"({"success":false,"error":"access denied"})";
            }
            json entries = json::array();
            const size_t cap = 500;
            if (recursive) {
                for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied);
                     it != fs::recursive_directory_iterator() && entries.size() < cap; ++it) {
                    json e;
                    e["path"] = it->path().string();
                    e["is_dir"] = it->is_directory();
                    entries.push_back(e);
                }
            } else {
                for (auto it = fs::directory_iterator(root, fs::directory_options::skip_permission_denied);
                     it != fs::directory_iterator() && entries.size() < cap; ++it) {
                    json e;
                    e["path"] = it->path().string();
                    e["is_dir"] = it->is_directory();
                    entries.push_back(e);
                }
            }
            json resp;
            resp["success"] = true;
            resp["count"] = entries.size();
            resp["entries"] = entries;
            return resp.dump();
        } catch (const std::exception& e) {
            return std::string("{\"success\":false,\"error\":") + JsonEscape(e.what()) + "}";
        }
    });
}

} // namespace

void ToolRegistry::register_tool(const std::string& name, ToolFunc fn) {
    std::lock_guard<std::mutex> lock(tools_mutex);
    tools[name] = fn;
}

std::string ToolRegistry::list_tools() {
    std::lock_guard<std::mutex> lock(tools_mutex);
    std::stringstream ss;
    for (const auto& kv : tools) {
        ss << "- " << kv.first << "\n";
    }
    return ss.str();
}

void ToolRegistry::inject_tools(AgentRequest& req) {
    const std::string tools_snapshot = list_tools();
    if (!tools_snapshot.empty()) {
        req.prompt = "[TOOLS AVAILABLE]\n" + tools_snapshot + "\n" + req.prompt;
    }
}

bool ToolRegistry::has_tool(const std::string& name) {
    std::lock_guard<std::mutex> lock(tools_mutex);
    return tools.find(name) != tools.end();
}

bool ToolRegistry::execute_tool(const std::string& name, const std::string& params_json, std::string& out_result) {
    ToolFunc fn;
    {
        std::lock_guard<std::mutex> lock(tools_mutex);
        const auto it = tools.find(name);
        if (it == tools.end()) {
            return false;
        }
        fn = it->second;
    }
    out_result = fn(params_json);
    return true;
}

void ToolRegistry::ensure_core_tools() {
    std::call_once(tools_once, []() {
        RegisterCoreTools();
        register_rawr_inference();
        register_git_mcp_tools();
        register_sovereign_engines();
    });
}

extern "C" __declspec(dllexport) void* __stdcall InitializeToolRegistry() {
    ToolRegistry::ensure_core_tools();
    return reinterpret_cast<void*>(1);
}

extern "C" __declspec(dllexport) int __stdcall ExecuteToolByName(
    const char* tool_name,
    const char* json_params,
    char* result_buffer,
    unsigned long long buffer_size) {
    if (tool_name == nullptr || result_buffer == nullptr || buffer_size == 0) {
        return -32600;
    }

    ToolRegistry::ensure_core_tools();
    std::string result;
    const std::string params = (json_params != nullptr) ? json_params : "{}";
    if (!ToolRegistry::execute_tool(tool_name, params, result)) {
        return -32601;
    }

    const size_t max_copy = static_cast<size_t>(buffer_size - 1);
    const size_t n = std::min(max_copy, result.size());
    memcpy(result_buffer, result.data(), n);
    result_buffer[n] = 0;
    return 0;
}
