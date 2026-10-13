/**
 * @file rawr_core.cpp
 * @brief Implementation of the RawrXD shared native core.
 */
#include "rawr_core.hpp"

namespace rawr {

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tool registry
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

void ToolRegistry::registerTool(const std::string& name, const std::string& description,
                                const std::string& argsSchema, unsigned requiredCaps,
                                Handler handler) {
    Entry e;
    e.name = name;
    e.description = description;
    e.argsSchema = argsSchema;
    e.caps = requiredCaps;
    e.handler = std::move(handler);
    tools_[name] = std::move(e);
}

std::vector<std::string> ToolRegistry::names() const {
    std::vector<std::string> out;
    out.reserve(tools_.size());
    for (const auto& [k, v] : tools_) out.push_back(k);
    return out;
}

const json& ToolRegistry::describe(const std::string& name) const {
    static const json kEmpty = json::object();
    auto it = tools_.find(name);
    if (it == tools_.end()) return kEmpty;
    static thread_local json cached;
    cached = json::object();
    cached["name"] = it->second.name;
    cached["description"] = it->second.description;
    try { cached["args"] = json::parse(it->second.argsSchema); }
    catch (...) { cached["args_raw"] = it->second.argsSchema; }
    cached["required_capability"] = it->second.caps != CAP_NONE ? "see caps" : "none";
    cached["read"] = (it->second.caps & CAP_READ) != 0;
    cached["search"] = (it->second.caps & CAP_SEARCH) != 0;
    cached["execute"] = (it->second.caps & CAP_EXEC) != 0;
    cached["write"] = (it->second.caps & CAP_WRITE) != 0;
    return cached;
}

ToolResult ToolRegistry::dispatch(const std::string& name, const json& args,
                                  const ToolContext& ctx) const {
    ToolResult r;
    r.tool = name;
    r.argsJson = args.dump();

    auto it = tools_.find(name);
    if (it == tools_.end()) {
        r.output = "ERROR: unknown tool '" + name + "'. Registered tools: " +
                   [&] {
                       std::string s;
                       for (const auto& n : names()) s += n + ", ";
                       return s;
                   }();
        r.ok = false;
        return r;
    }

    // â”€â”€ Permission policy enforced in the dispatcher â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const ModeProfile* mode = ctx.mode;
    if (!mode) {
        r.output = "ERROR: no active mode profile; tool dispatch denied";
        r.ok = false;
        return r;
    }
    if ((it->second.caps & mode->caps) != it->second.caps) {
        unsigned missing = it->second.caps & ~mode->caps;
        std::string m;
        for (unsigned bit = 1; bit <= CAP_WRITE; bit <<= 1)
            if (missing & bit) m += std::string(capName(bit)) + " ";
        r.denied = true;
        r.ok = false;
        r.output = "DENIED: mode '" + std::string(mode->name) +
                   "' lacks capability required by tool '" + name + "' (needs: " + m +
                   "). Mode permissions are enforced in the tool dispatcher, not by "
                   "the model.";
        return r;
    }

    // Plan-only modes may only write plan artifacts.
    if (mode->planFilesOnly && (it->second.caps & CAP_WRITE)) {
        std::string rel = ctx.ws ? ctx.ws->toRelative(args.value("path", std::string()))
                                 : std::string();
        if (!(toLower(rel).find("plan") != std::string::npos ||
              toLower(rel).find(".plan") != std::string::npos)) {
            r.denied = true;
            r.ok = false;
            r.output = "DENIED: mode '" + std::string(mode->name) +
                       "' may only write plan artifacts; refusing to write '" + rel + "'";
            return r;
        }
    }

    try {
        r = it->second.handler(args, ctx);
    } catch (const std::exception& e) {
        r.ok = false;
        r.output = std::string("ERROR: tool threw ") + e.what();
    } catch (...) {
        r.ok = false;
        r.output = "ERROR: tool threw an unknown exception";
    }
    r.tool = name;
    r.argsJson = args.dump();
    if (r.exitCode == 0 && !r.ok) r.exitCode = 1;  // non-zero for automation
    return r;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Walk helper shared by the filesystem tools
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

static bool isExcludedFromWalk(const fs::path& p) {
    std::string lower = toLower(p.filename().string());
    static const char* dirs[] = {
        ".git",    "3rdparty",  "build",      "build_vs",  "build_fresh",
        "build_cert", "build_test", "out",    "__pycache__", "node_modules",
        "vs_validation", ".cache", "dist",   "~dev",       "_deps",
        "bench",   ".swarm_runs", "evidence", "crash_dumps"
    };
    for (const char* d : dirs)
        if (lower == d) return true;

    for (const char* ext : {".gguf", ".dll", ".exe", ".pdb", ".lib", ".obj",
                             ".zip", ".7z", ".iso", ".bin"})
        if (lower.size() > strlen(ext) &&
            lower.compare(lower.size() - strlen(ext), strlen(ext), ext) == 0)
            return true;
    return false;
}

// Source-like extension filter (RAWRXD_SEARCH_SCOPE_001): code questions are
// answered from source files; logs and generated text pollute the hit list.
static bool isSourceLikePath(const fs::path& p) {
    std::string e = toLower(p.extension().string());
    static const char* kExt[] = {
        ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hh", ".inl", ".ipp",
        ".asm", ".s", ".inc", ".cu", ".cuh", ".metal", ".glsl", ".hlsl",
        ".vert", ".frag", ".comp", ".py", ".rs", ".go", ".java", ".cs",
        ".js", ".jsx", ".ts", ".tsx", ".m", ".mm", ".swift", ".kt",
        ".md", ".txt", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".cfg",
        ".bat", ".ps1", ".sh", ".cmake", ".gnf", ".gnf"
    };
    for (const char* s : kExt)
        if (e == s) return true;
    return false;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Default tools
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

void registerDefaultTools(ToolRegistry& reg, const Workspace& ws) {
    // â”€â”€ list_repo â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    reg.registerTool(
        "list_repo", "Recursively list files under a workspace-relative path",
        R"({"path":{"type":"string","description":"workspace-relative path"}})",
        CAP_READ,
        [&ws](const json& args, const ToolContext&) -> ToolResult {
            ToolResult r;
            r.tool = "list_repo";
            std::string abs = ws.resolve(args.value("path", std::string(".")), true);
            if (abs.empty()) {
                r.output = "ERROR: path outside workspace or not found: " +
                           args.value("path", std::string());
                return r;
            }
            std::ostringstream os;
            int count = 0;
            bool aborted = false;
            try {
                std::error_code ec;
                fs::recursive_directory_iterator it(
                    abs, fs::directory_options::skip_permission_denied, ec);
                if (ec) { r.output = "ERROR: cannot iterate " + abs; return r; }
                for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
                    if (ec) { aborted = true; break; }
                    if (count >= 4000) { aborted = true; break; }
                    if (isExcludedFromWalk(it->path())) {
                        it.disable_recursion_pending();
                        continue;
                    }
                    if (!it->is_regular_file(ec)) continue;
                    if (count < 300) os << ws.relOf(it->path()) << "\n";
                    ++count;
                }
            } catch (const std::exception& e) {
                r.output = std::string("ERROR: walk failed: ") + e.what();
                return r;
            }
            std::ostringstream head;
            head << "root=" << abs << "\nentries=" << count << "\n";
            if (aborted) head << "NOTE: bounded at 4000 entries\n";
            r.output = head.str() + os.str();
            r.ok = true;
            return r;
        });

    // â”€â”€ read_file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    reg.registerTool(
        "read_file", "Read up to 60KB of a workspace file",
        R"({"path":{"type":"string"}})",
        CAP_READ,
        [&ws](const json& args, const ToolContext&) -> ToolResult {
            ToolResult r;
            r.tool = "read_file";
            std::string rel = args.value("path", std::string());
            std::string abs = ws.resolve(rel, true);
            if (abs.empty()) {
                r.output = "ERROR: file outside workspace or not found: " + rel;
                return r;
            }
            std::error_code ec;
            if (!fs::is_regular_file(fs::path(abs), ec) || ec) {
                r.output = "ERROR: not a regular file: " + rel +
                           " (use list_repo to discover real paths)";
                return r;
            }
            uintmax_t sz = fs::file_size(fs::path(abs), ec);
            if (!ec && sz > 4u * 60u * 1024u) {
                r.output = "ERROR: file too large (" + std::to_string(sz) +
                           " bytes). Use search_text or read a smaller file: " + rel;
                return r;
            }
            try {
                std::ifstream f(abs, std::ios::binary);
                if (!f) { r.output = "ERROR: cannot open " + rel; return r; }
                std::string content((std::istreambuf_iterator<char>(f)),
                                    std::istreambuf_iterator<char>());
                if (content.empty()) { r.output = "(empty) " + rel; r.ok = true; return r; }
                r.output = truncateForLedger(content, 60 * 1024);
                r.ok = true;
                return r;
            } catch (const std::exception& e) {
                r.output = std::string("ERROR: read failed ") + e.what();
                return r;
            }
        });

    // â”€â”€ search_text â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    reg.registerTool(
        "search_text", "Case-insensitive text search across the workspace",
        R"({"query":{"type":"string"},"path":{"type":"string","description":"root"},"all":{"type":"boolean","description":"search every text file, not just source extensions"}})",
        CAP_SEARCH,
        [&ws](const json& args, const ToolContext&) -> ToolResult {
            ToolResult r;
            r.tool = "search_text";
            std::string query = args.value("query", std::string());
            if (query.empty()) { r.output = "ERROR: empty query"; return r; }
            std::string q = toLower(query);
            const bool searchAll = args.value("all", false);  // RAWRXD_SEARCH_SCOPE_001
            std::string abs = ws.resolve(args.value("path", std::string(".")), true);
            if (abs.empty()) {
                r.output = "ERROR: search root outside workspace or not found";
                return r;
            }
            std::ostringstream os;
            int hits = 0, scanned = 0;
            bool aborted = false;
            try {
                std::error_code ec;
                fs::recursive_directory_iterator it(
                    abs, fs::directory_options::skip_permission_denied, ec);
                if (ec) { r.output = "ERROR: cannot iterate " + abs; return r; }
                for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
                    if (ec) { aborted = true; break; }
                    if (scanned >= 4000) { aborted = true; break; }
                    if (isExcludedFromWalk(it->path())) {
                        it.disable_recursion_pending();
                        continue;
                    }
                    if (!it->is_regular_file(ec)) continue;
                    ++scanned;
                    if (hits >= 40) continue;
                    // Source-scope: skip text-shaped build artifacts (logs,
                    // cmake output, .o stubs, caches) unless all=true.
                    if (!searchAll && !isSourceLikePath(it->path())) continue;
                    std::ifstream f(it->path(), std::ios::binary);
                    if (!f) continue;
                    std::string content((std::istreambuf_iterator<char>(f)),
                                        std::istreambuf_iterator<char>());
                    if (toLower(content).find(q) == std::string::npos) continue;
                    ++hits;
                    os << ws.relOf(it->path()) << "\n";
                }
            } catch (const std::exception& e) {
                r.output = std::string("ERROR: search failed ") + e.what();
                return r;
            }
            std::ostringstream head;
            head << "query=" << query << "\nroot=" << abs << "\nfiles_scanned=" << scanned
                 << "\nmatching_files=" << hits << "\n";
            if (aborted) head << "NOTE: scan bounded at 4000 files\n";
            r.output = head.str() + os.str();
            r.ok = true;
            return r;
        });

    // â”€â”€ git_status â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    reg.registerTool(
        "git_status", "Read-only porcelain git status for the workspace",
        R"({})",
        CAP_EXEC,
        [&ws](const json&, const ToolContext&) -> ToolResult {
            ToolResult r;
            r.tool = "git_status";
            CommandResult c = runBoundedCommand("git status --porcelain=v1 --branch",
                                                ws.root(), 60000);
            r.output = c.output;
            r.ok = c.launched && c.completed;
            r.exitCode = c.exitCode;
            if (!c.error.empty()) r.output += "\nERROR: " + c.error;
            return r;
        });

    // â”€â”€ write_file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    reg.registerTool(
        "write_file", "Create/modify a workspace file (overwrite is backed up first)",
        R"({"path":{"type":"string"},"action":{"type":"string","enum":["replace","append"]},
            "content":{"type":"string"}})",
        CAP_WRITE,
        [&ws](const json& args, const ToolContext& ctx) -> ToolResult {
            ToolResult r;
            r.tool = "write_file";
            std::string rel = args.value("path", std::string());
            std::string action = args.value("action", std::string("replace"));
            std::string content = args.value("content", std::string());

            if (rel.empty() || content.empty()) {
                r.output = "ERROR: path and content are required";
                return r;
            }
            std::string abs = ws.resolve(rel, false);
            if (abs.empty()) {
                r.output = "ERROR: path escapes the workspace: " + rel;
                return r;
            }
            // Source edits are additionally gated by the active mode.
            if (ctx.mode && !ctx.mode->sourceEditsAllowed) {
                std::string l = toLower(rel);
                bool isSource = l.find("src/") == 0 || l.find("src\\") == 0 ||
                                l.find("include/") == 0 || l.size() > 4 &&
                                (l.substr(l.size() - 4) == ".cpp" ||
                                 l.substr(l.size() - 4) == ".hpp");
                if (isSource) {
                    r.denied = true;
                    r.output = "DENIED: mode '" + std::string(ctx.mode->name) +
                               "' does not permit editing project source: " + rel;
                    return r;
                }
            }

            try {
                std::error_code ec;
                std::string relp = ws.toRelative(rel);
                fs::path relFs(relp);
                if (relFs.has_parent_path())
                    fs::create_directories(fs::path(ws.root()) / relFs.parent_path(), ec);

                fs::path target(abs);
                bool existed = fs::exists(target);
                uintmax_t before = existed ? fs::file_size(target, ec) : 0;

                std::string backup;
                if (existed && action == "replace") {
                    std::error_code bec;
                    backup = abs + ".auditbak." + std::to_string(GetTickCount64());
                    fs::copy_file(target, fs::path(backup),
                                  fs::copy_options::overwrite_existing, bec);
                    if (bec) {
                        r.output = "ERROR: backup failed (" + bec.message() +
                                   ") - refusing to modify " + rel;
                        return r;
                    }
                }

                std::ofstream f(target, std::ios::binary |
                                            (action == "append" ? std::ios::app
                                                                : std::ios::trunc));
                if (!f) { r.output = "ERROR: cannot open for writing " + rel; return r; }
                f.write(content.data(), static_cast<std::streamsize>(content.size()));
                f.flush();
                if (!f) {
                    r.output = "ERROR: write failed for " + rel + " (partial write)";
                    return r;
                }
                f.close();
                uintmax_t after = fs::file_size(target, ec);

                std::ostringstream os;
                os << "WROTE " << relp << "\naction=" << action
                   << "\nbytes_written=" << content.size()
                   << "\nsize_before=" << before << "\nsize_after=" << after << "\n";
                if (!backup.empty())
                    os << "backup=" << fs::path(backup).filename().string() << "\n";
                r.output = os.str();
                r.ok = true;
                return r;
            } catch (const std::exception& e) {
                r.output = std::string("ERROR: write threw ") + e.what();
                return r;
            }
        });

    // â”€â”€ run_build â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    reg.registerTool(
        "run_build", "Invoke the CMake build for the workspace",
        R"({"config":{"type":"string","default":"Release"}})",
        CAP_EXEC,
        [&ws](const json& args, const ToolContext&) -> ToolResult {
            ToolResult r;
            r.tool = "run_build";
            std::string config = args.value("config", std::string("Release"));
            CommandResult c = runBoundedCommand(
                "cmake --build build_vs --config " + config, ws.root(), 900000);
            r.output = c.output;
            r.ok = c.launched && c.completed && c.exitCode == 0;
            r.exitCode = c.exitCode;
            if (!c.completed) r.output += "\nBUILD_DID_NOT_COMPLETE (timeout)";
            return r;
        });

    // â”€â”€ run_tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    reg.registerTool(
        "run_tests", "Invoke the CTest suite for the workspace",
        R"({"filter":{"type":"string"}})",
        CAP_EXEC,
        [&ws](const json& args, const ToolContext&) -> ToolResult {
            ToolResult r;
            r.tool = "run_tests";
            std::string filter = args.value("filter", std::string());
            std::string cmd = "ctest --test-dir build_vs --output-on-failure";
            if (!filter.empty()) cmd += " -R " + filter;
            CommandResult c = runBoundedCommand(cmd, ws.root(), 900000);
            r.output = c.output;
            r.ok = c.launched && c.completed && c.exitCode == 0;
            r.exitCode = c.exitCode;
            if (!c.completed) r.output += "\nTESTS_DID_NOT_COMPLETE (timeout)";
            return r;
        });
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Inference client
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

void InferenceClient::setEndpoint(int port, const std::string& host,
                                  const std::string& path) {
    port_ = port;
    host_ = utf8ToWide(host);
    path_ = path;
}

std::string InferenceClient::httpPost(const std::string& path, const std::string& body,
                                      long* status, std::string& err) {
    std::string response;
    HINTERNET session = WinHttpOpen(L"RawrXDCore/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { err = "WinHttpOpen failed"; return {}; }
    HINTERNET conn = WinHttpConnect(session, host_.c_str(),
                                    static_cast<INTERNET_PORT>(port_), 0);
    if (!conn) { err = "WinHttpConnect failed"; WinHttpCloseHandle(session); return {}; }
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", utf8ToWide(path).c_str(), nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) {
        err = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return {};
    }

    // Timeouts must be set before the request is sent.
    DWORD t = static_cast<DWORD>(timeoutMs_);
    WinHttpSetTimeouts(req, t, t, t, t);

    if (!WinHttpSendRequest(req, L"Content-Type: application/json\r\n", -1L,
                            const_cast<char*>(body.data()),
                            static_cast<DWORD>(body.size()),
                            static_cast<DWORD>(body.size()), 0)) {
        err = "WinHttpSendRequest failed (" + std::to_string(GetLastError()) + ")";
        goto cleanup;
    }
    if (!WinHttpReceiveResponse(req, nullptr)) {
        err = "WinHttpReceiveResponse failed (" + std::to_string(GetLastError()) + ")";
        goto cleanup;
    }

    {
        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz,
                            WINHTTP_NO_HEADER_INDEX);
        if (status) *status = static_cast<long>(code);

        for (;;) {
            DWORD have = 0;
            if (!WinHttpQueryDataAvailable(req, &have)) break;
            if (have == 0) break;
            std::vector<char> buf(static_cast<size_t>(have) + 1, 0);
            DWORD rd = 0;
            if (!WinHttpReadData(req, buf.data(), have, &rd)) break;
            if (rd == 0) break;
            response.append(buf.data(), rd);
        }
    }

cleanup:
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return response;
}

bool InferenceClient::ping(int timeoutMs) {
    int saved = timeoutMs_;
    timeoutMs_ = 60000;
    std::vector<json> probe = {{{"role", "user"}, {"content", "Reply with the word: ready"}}};
    InferenceResult r = complete(probe, 8);
    timeoutMs_ = saved;
    return r.ok;
}

InferenceResult InferenceClient::complete(const std::vector<json>& messages,
                                          int maxTokens, double temperature) {
    InferenceResult out;
    json payload;
    payload["model"] = model_;
    payload["messages"] = messages;
    payload["max_tokens"] = maxTokens;
    payload["temperature"] = temperature;
    payload["stream"] = false;

    for (int attempt = 1; attempt <= 3; ++attempt) {
        long status = 0;
        std::string err;
        std::string raw = httpPost(path_, payload.dump(), &status, err);
        if (raw.empty()) {
            out.error = "HTTP transport failure (attempt " + std::to_string(attempt) +
                        "): " + err;
            if (attempt < 3) Sleep(1500);
            continue;
        }
        if (status != 200) {
            out.error = "HTTP status " + std::to_string(status) + ": " +
                        truncateForLedger(raw, 300);
            return out;
        }
        try {
            json doc = json::parse(raw);
            // Backend fields may legitimately be null or absent (llama.cpp
            // returns "usage": null very often, and tool-only or truncated
            // replies can leave "message": {"content": null}). Reading them
            // with operator[]/.value() on a null node throws
            // type_error.306, which previously escaped as a host crash. Guard
            // each optional field; never fabricate a successful-but-empty row.
            const json& choices = (doc.is_object() && doc.contains("choices") &&
                                   doc["choices"].is_array() && !doc["choices"].empty())
                                      ? doc["choices"]
                                      : json::array();
            for (const auto& c : choices) {
                if (!c.is_object() || !c.contains("message")) continue;
                const auto& msg = c["message"];
                if (!msg.is_object()) continue;
                if (msg.contains("content") && msg["content"].is_string())
                    out.content = msg["content"].get<std::string>();
                if (c.contains("finish_reason") && c["finish_reason"].is_string())
                    out.finishReason = c["finish_reason"].get<std::string>();
            }
            if (doc.is_object() && doc.contains("usage") && doc["usage"].is_object()) {
                out.promptTokens = doc["usage"].value("prompt_tokens", 0);
                out.completionTokens = doc["usage"].value("completion_tokens", 0);
            }
            out.ok = true;
            out.error.clear();
            return out;
        } catch (const std::exception& e) {
            out.ok = false;
            out.error = std::string("JSON parse failure: ") + e.what();
            return out;
        }
    }
    return out;
}

}  // namespace rawr
