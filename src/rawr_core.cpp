/**
 * @file rawr_core.cpp
 * @brief Implementation of the RawrXD shared native core.
 */
#include "rawr_core.hpp"
#include "rawr_edit_rollback.hpp"

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

    // Strict schema gate: reject unknown keys and missing required fields.
    // Schema shape: {"field":{"type":"...","required":true,"default":"..."}}
    try {
        json schema = json::parse(it->second.argsSchema);
        if (schema.is_object()) {
            for (auto itArg = args.begin(); itArg != args.end(); ++itArg) {
                if (!schema.contains(itArg.key())) {
                    r.ok = false;
                    r.output = "ERROR: unknown arg '" + itArg.key() +
                               "' for tool '" + name + "' (strict schema)";
                    return r;
                }
            }
            for (auto itSch = schema.begin(); itSch != schema.end(); ++itSch) {
                const bool required =
                    itSch.value().is_object() &&
                    itSch.value().value("required", false) == true;
                if (required && !args.contains(itSch.key())) {
                    r.ok = false;
                    r.output = "ERROR: missing required arg '" + itSch.key() +
                               "' for tool '" + name + "'";
                    return r;
                }
            }
        }
    } catch (...) {
        // Malformed schema is a host bug: fail closed rather than dispatch.
        r.ok = false;
        r.output = "ERROR: tool schema parse failed for '" + name + "'";
        return r;
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

/**
 * @brief Read a text file and return it as UTF-8.
 *
 * This tree contains UTF-16-encoded sources (BOMs such as FF FE are present).
 * A byte-level ASCII search against those files silently finds nothing, which
 * is the worst failure mode: it reports a confident, wrong count instead of
 * reporting that it could not read a file. Decoding here makes read_file and
 * search_text see the same content any editor would.
 */
static bool readTextUtf8(const std::string& path, std::string& out,
                         std::string& detectedEncoding) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::string raw((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
    if (raw.empty()) { out.clear(); detectedEncoding = "empty"; return true; }

    auto hasPrefix = [&](const char* p, size_t n) {
        return raw.size() >= n && std::memcmp(raw.data(), p, n) == 0;
    };

    // UTF-16 LE with BOM
    if (hasPrefix("\xFF\xFE", 2)) {
        detectedEncoding = "utf-16le";
        std::string body = raw.substr(2);
        out.clear();
        out.reserve(body.size());
        for (size_t i = 0; i + 1 < body.size(); i += 2) {
            unsigned short u =
                (unsigned char)body[i] | ((unsigned char)body[i + 1] << 8);
            if (u < 0x80) {
                out += static_cast<char>(u);
            } else if (u < 0x800) {
                out += static_cast<char>(0xC0 | (u >> 6));
                out += static_cast<char>(0x80 | (u & 0x3F));
            } else {
                out += static_cast<char>(0xE0 | (u >> 12));
                out += static_cast<char>(0x80 | ((u >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (u & 0x3F));
            }
        }
        return true;
    }
    // UTF-16 BE with BOM
    if (hasPrefix("\xFE\xFF", 2)) {
        detectedEncoding = "utf-16be";
        std::string body = raw.substr(2);
        out.clear();
        out.reserve(body.size());
        for (size_t i = 0; i + 1 < body.size(); i += 2) {
            unsigned short u =
                ((unsigned char)body[i] << 8) | (unsigned char)body[i + 1];
            if (u < 0x80) {
                out += static_cast<char>(u);
            } else if (u < 0x800) {
                out += static_cast<char>(0xC0 | (u >> 6));
                out += static_cast<char>(0x80 | (u & 0x3F));
            } else {
                out += static_cast<char>(0xE0 | (u >> 12));
                out += static_cast<char>(0x80 | ((u >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (u & 0x3F));
            }
        }
        return true;
    }
    // UTF-8 with BOM (strip the BOM so content matches cleanly)
    if (hasPrefix("\xEF\xBB\xBF", 3)) {
        detectedEncoding = "utf-8-bom";
        out = raw.substr(3);
        return true;
    }

    detectedEncoding = "utf-8";
    out = raw;
    return true;
}

static bool isExcludedFromWalk(const fs::path& p) {
    // A filename that cannot be represented in the current code page (non-ASCII
    // names exist in this tree) must not abort the whole scan. Degrade to the
    // native wide form instead of throwing.
    std::string name;
    try {
        name = p.filename().string();
    } catch (const std::exception&) {
        name = "";
    }
    if (name.empty()) return false;  // never exclude on a conversion failure
    std::string lower = toLower(name);
    static const char* dirs[] = {
        ".git",    "3rdparty",  "build",      "build_vs",  "build_fresh",
        "build_cert", "build_test", "out",    "__pycache__", "node_modules",
        "vs_validation", ".cache", "dist",   "~dev",       "_deps",
        "bench",   ".swarm_runs", "evidence", "crash_dumps",
        ".archive", "_archive", "_pre_merge_backup", ".backups", "logs",
        "full_source", "full source", "tmp_build"
    };
    for (const char* d : dirs)
        if (lower == d) return true;

    for (const char* ext : {".gguf", ".dll", ".exe", ".pdb", ".lib", ".obj",
                             ".zip", ".7z", ".iso", ".bin", ".log", ".tmp",
                             ".exp", ".ilk"})
        if (lower.size() > strlen(ext) &&
            lower.compare(lower.size() - strlen(ext), strlen(ext), ext) == 0)
            return true;
    return false;
}

// Source-like extension filter (RAWRXD_SEARCH_SCOPE_001): code questions are
// answered from source files. Data/markup/build-script text (.json, .md, .txt,
// .yaml, .bat ...) is excluded from DEFAULT scope so it cannot pollute hits;
// it remains reachable only via an explicit all=true search on an authorized path.
static bool isSourceLikePath(const fs::path& p) {
    // Never throw on an unrepresentable extension; treat it as non-source.
    std::string e;
    try { e = toLower(p.extension().string()); } catch (const std::exception&) { return false; }
    static const char* kExt[] = {
        ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hh", ".inl", ".ipp",
        ".asm", ".s", ".inc", ".cu", ".cuh", ".metal", ".glsl", ".hlsl",
        ".vert", ".frag", ".comp", ".py", ".rs", ".go", ".java", ".cs",
        ".js", ".jsx", ".ts", ".tsx", ".m", ".mm", ".swift", ".kt"
    };
    for (const char* s : kExt)
        if (e == s) return true;
    return false;
}

// ALWAYS-ENFORCED access policy (RAWRXD_SOURCE_AUTH_001). This is separate from
// isExcludedFromWalk (which only governs DEFAULT discovery). No scope flag --
// including all=true -- may bypass this. Secrets, VCS internals and crash/backup
// dumps are never readable through any tool. Deny-by-default on any doubt.
static bool isPathAuthorized(const fs::path& p) {
    std::vector<std::string> parts;
    try {
        for (const auto& part : p) parts.push_back(toLower(part.string()));
    } catch (...) {
        return false;  // unrepresentable path component: refuse
    }
    for (const auto& s : parts) {
        if (s == ".git" || s == ".archive" || s == "_archive" ||
            s == "crash_dumps" || s == ".backups" || s == "_pre_merge_backup")
            return false;
    }
    std::string name;
    try { name = toLower(p.filename().string()); } catch (...) { return false; }
    if (name.empty()) return true;
    static const char* blocked[] = {
        ".env", ".pem", ".key", ".keystore", ".p12", ".pfx", ".ppk",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials", "secrets"
    };
    for (const char* b : blocked)
        if (name.find(b) != std::string::npos) return false;
    return true;
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
                    if (!isPathAuthorized(it->path())) continue;
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
        R"({"path":{"type":"string","required":true}})",
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
            if (!isPathAuthorized(fs::path(abs))) {
                r.output = "ERROR: access denied (restricted path): " + rel;
                return r;
            }
            uintmax_t sz = fs::file_size(fs::path(abs), ec);
            if (!ec && sz > 4u * 60u * 1024u) {
                r.output = "ERROR: file too large (" + std::to_string(sz) +
                           " bytes). Use search_text or read a smaller file: " + rel;
                return r;
            }
            try {
                std::string content, enc;
                if (!readTextUtf8(abs, content, enc)) {
                    r.output = "ERROR: cannot open " + rel;
                    return r;
                }
                if (content.empty()) {
                    r.output = "(empty) " + rel;
                    r.ok = true;
                    return r;
                }
                r.output = truncateForLedger(content, 60 * 1024) +
                           "\n[encoding=" + enc + "]";
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
                // Single-file search: path may be a regular file (not only a dir).
                if (fs::is_regular_file(fs::path(abs), ec) && !ec) {
                    if (!isPathAuthorized(fs::path(abs))) {
                        r.output = "ERROR: access denied (restricted path)";
                        return r;
                    }
                    ++scanned;
                    std::string content, enc;
                    if (readTextUtf8(abs, content, enc) &&
                        toLower(content).find(q) != std::string::npos) {
                        ++hits;
                        os << ws.relOf(fs::path(abs)) << " [" << enc << "]\n";
                    }
                    std::ostringstream head;
                    head << "query=" << query << "\nroot=" << abs
                         << "\nfiles_scanned=" << scanned
                         << "\nmatching_files=" << hits << "\n";
                    r.output = head.str() + os.str();
                    r.ok = true;
                    return r;
                }
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
                    // Always-enforced authorization; all=true cannot bypass it.
                    if (!isPathAuthorized(it->path())) continue;
                    ++scanned;
                    if (hits >= 40) continue;
                    // Source-scope: skip text-shaped build artifacts (logs,
                    // cmake output, .o stubs, caches) unless all=true.
                    try {
                        if (!searchAll && !isSourceLikePath(it->path())) continue;
                        std::string content, enc;
                        if (!readTextUtf8(it->path().string(), content, enc)) continue;
                        if (toLower(content).find(q) == std::string::npos) continue;
                        ++hits;
                        os << ws.relOf(it->path()) << " [" << enc << "]\n";
                    } catch (const std::exception&) {
                        // A file that cannot be read or represented is skipped,
                        // never allowed to abort the whole search.
                        continue;
                    }
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
        R"({"path":{"type":"string","required":true},"action":{"type":"string","enum":["replace","append"],"default":"replace"},
            "content":{"type":"string","required":true}})",
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
        R"({"config":{"type":"string","default":"Release"},"dir":{"type":"string","description":"workspace-relative project dir with CMakeLists.txt"}})",
        CAP_EXEC,
        [&ws](const json& args, const ToolContext&) -> ToolResult {
            ToolResult r;
            r.tool = "run_build";
            std::string config = args.value("config", std::string("Release"));
            std::string dir = args.value("dir", std::string());
            std::string cmd;
            if (!dir.empty()) {
                std::string abs = ws.resolve(dir, true);
                if (abs.empty()) {
                    r.output = "ERROR: build dir outside workspace or not found: " + dir;
                    return r;
                }
                std::string bdir = abs + "\\build";
                CommandResult cfg = runBoundedCommand(
                    "cmake -S \"" + abs + "\" -B \"" + bdir + "\"", ws.root(), 300000);
                r.output = cfg.output;
                if (!(cfg.launched && cfg.completed && cfg.exitCode == 0)) {
                    r.ok = false;
                    r.exitCode = cfg.exitCode;
                    if (!cfg.completed) r.output += "\nBUILD_CONFIGURE_DID_NOT_COMPLETE";
                    return r;
                }
                cmd = "cmake --build \"" + bdir + "\" --config " + config;
            } else {
                // Prefer the live IDE build tree when present; fall back through
                // common local cmake dirs instead of hard-failing on build_vs.
                std::string bdir = "build_vs";
                for (const char* cand : {"build_ide", "build", "build_vs", "build_ninja"}) {
                    std::error_code bec;
                    if (fs::exists(fs::path(ws.root()) / cand, bec) && !bec) {
                        bdir = cand;
                        break;
                    }
                }
                cmd = "cmake --build " + bdir + " --config " + config;
            }
            CommandResult c = runBoundedCommand(cmd, ws.root(), 900000);
            r.output += c.output;
            r.ok = c.launched && c.completed && c.exitCode == 0;
            r.exitCode = c.exitCode;
            if (!c.completed) r.output += "\nBUILD_DID_NOT_COMPLETE (timeout)";
            return r;
        });

    // â”€â”€ run_tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    reg.registerTool(
        "run_tests", "Invoke the CTest suite for the workspace",
        R"({"filter":{"type":"string"},"dir":{"type":"string","description":"workspace-relative project dir"},"config":{"type":"string","default":"Debug"}})",
        CAP_EXEC,
        [&ws](const json& args, const ToolContext&) -> ToolResult {
            ToolResult r;
            r.tool = "run_tests";
            std::string filter = args.value("filter", std::string());
            std::string dir = args.value("dir", std::string());
            std::string config = args.value("config", std::string("Debug"));
            std::string testDir = "build_vs";
            for (const char* cand : {"build_ide", "build", "build_vs", "build_ninja"}) {
                std::error_code bec;
                if (fs::exists(fs::path(ws.root()) / cand, bec) && !bec) {
                    testDir = cand;
                    break;
                }
            }
            if (!dir.empty()) {
                std::string abs = ws.resolve(dir, true);
                if (abs.empty()) {
                    r.output = "ERROR: test dir outside workspace or not found: " + dir;
                    return r;
                }
                testDir = abs + "\\build";
            }
            std::string cmd = "ctest --test-dir \"" + testDir + "\" --output-on-failure";
            if (!config.empty()) cmd += " -C " + config;
            if (!filter.empty()) cmd += " -R " + filter;
            CommandResult c = runBoundedCommand(cmd, ws.root(), 900000);
            r.output = c.output;
            r.ok = c.launched && c.completed && c.exitCode == 0;
            r.exitCode = c.exitCode;
            if (!c.completed) r.output += "\nTESTS_DID_NOT_COMPLETE (timeout)";
            return r;
        });

    // â”€â”€ edit_files â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    reg.registerTool(
        "edit_files", "Replace exact unique text in a workspace file",
        R"({"path":{"type":"string","required":true},"old":{"type":"string","required":true},"new":{"type":"string","required":true}})",
        CAP_WRITE,
        [&ws](const json& args, const ToolContext& ctx) -> ToolResult {
            ToolResult r;
            r.tool = "edit_files";
            std::string rel = args.value("path", std::string());
            std::string oldStr = args.value("old", std::string());
            std::string newStr = args.value("new", std::string());

            if (rel.empty() || oldStr.empty()) {
                r.output = "ERROR: path and old are required";
                return r;
            }
            std::string abs = ws.resolve(rel, true);
            if (abs.empty()) {
                r.output = "ERROR: path escapes the workspace or missing: " + rel;
                return r;
            }
            if (!isPathAuthorized(fs::path(abs))) {
                r.output = "ERROR: access denied (restricted path): " + rel;
                return r;
            }
            if (ctx.mode && !ctx.mode->sourceEditsAllowed) {
                std::string l = toLower(rel);
                bool isSource = l.find("src/") == 0 || l.find("src\\") == 0 ||
                                l.find("include/") == 0 || (l.size() > 4 &&
                                (l.substr(l.size() - 4) == ".cpp" ||
                                 l.substr(l.size() - 4) == ".hpp"));
                if (isSource) {
                    r.denied = true;
                    r.output = "DENIED: mode '" + std::string(ctx.mode->name) +
                               "' does not permit editing project source: " + rel;
                    return r;
                }
            }
            try {
                std::string content, enc;
                if (!readTextUtf8(abs, content, enc)) {
                    r.output = "ERROR: cannot read " + rel;
                    return r;
                }
                // Normalize CRLF so model/orchestrator LF snippets match Windows files.
                auto stripCr = [](std::string s) {
                    s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
                    return s;
                };
                content = stripCr(std::move(content));
                oldStr = stripCr(std::move(oldStr));
                newStr = stripCr(std::move(newStr));
                size_t pos = content.find(oldStr);
                if (pos == std::string::npos) {
                    r.output = "ERROR: old text not found in " + rel;
                    return r;
                }
                if (content.find(oldStr, pos + oldStr.size()) != std::string::npos) {
                    r.output = "ERROR: old text occurs more than once in " + rel;
                    return r;
                }
                // Snapshot pre-edit bytes for rollback_edit (C15).
                {
                    std::string serr;
                    if (!rawr_edit_rb::writeSnapshot(abs, content, &serr)) {
                        r.output = "ERROR: rollback snapshot failed: " + serr;
                        return r;
                    }
                }
                content.replace(pos, oldStr.size(), newStr);
                // Atomic replace: write temp then ReplaceFileW (no trunc-in-place).
                const std::string tmp = abs + ".rawrxd.edit.tmp";
                {
                    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
                    if (!f) { r.output = "ERROR: cannot write temp for " + rel; return r; }
                    f.write(content.data(), static_cast<std::streamsize>(content.size()));
                    f.close();
                    if (!f) {
                        r.output = "ERROR: temp write failed for " + rel;
                        fs::remove(tmp);
                        return r;
                    }
                }
                std::wstring wAbs = utf8ToWide(abs);
                std::wstring wTmp = utf8ToWide(tmp);
                if (!ReplaceFileW(wAbs.c_str(), wTmp.c_str(), nullptr,
                                  REPLACEFILE_IGNORE_MERGE_ERRORS, nullptr, nullptr)) {
                    // Fallback for first-create edge: MoveFileEx after delete.
                    if (!MoveFileExW(wTmp.c_str(), wAbs.c_str(),
                                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                        r.output = "ERROR: atomic replace failed for " + rel +
                                   " gle=" + std::to_string(GetLastError());
                        fs::remove(tmp);
                        return r;
                    }
                }
                r.output = "EDITED " + rel + " (" + std::to_string(newStr.size()) +
                           " bytes replacement, atomic; rollback snapshot saved)";
                r.ok = true;
                return r;
            } catch (const std::exception& e) {
                r.output = std::string("ERROR: edit failed ") + e.what();
                return r;
            }
        });

    // â”€â”€ rollback_edit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    reg.registerTool(
        "rollback_edit", "Restore last edit_files snapshot for a workspace path",
        R"({"path":{"type":"string","required":true}})",
        CAP_WRITE,
        [&ws](const json& args, const ToolContext& ctx) -> ToolResult {
            ToolResult r;
            r.tool = "rollback_edit";
            std::string rel = args.value("path", std::string());
            if (rel.empty()) { r.output = "ERROR: path is required"; return r; }
            std::string abs = ws.resolve(rel, true);
            if (abs.empty()) {
                r.output = "ERROR: path escapes the workspace or missing: " + rel;
                return r;
            }
            if (!isPathAuthorized(fs::path(abs))) {
                r.output = "ERROR: access denied (restricted path): " + rel;
                return r;
            }
            if (ctx.mode && !ctx.mode->sourceEditsAllowed) {
                std::string l = toLower(rel);
                bool isSource = l.find("src/") == 0 || l.find("src\\") == 0 ||
                                l.find("include/") == 0 || (l.size() > 4 &&
                                (l.substr(l.size() - 4) == ".cpp" ||
                                 l.substr(l.size() - 4) == ".hpp"));
                if (isSource) {
                    r.denied = true;
                    r.output = "DENIED: mode '" + std::string(ctx.mode->name) +
                               "' does not permit rollback of project source: " + rel;
                    return r;
                }
            }
            std::string msg;
            if (!rawr_edit_rb::restoreSnapshot(abs, &msg)) {
                r.output = msg;
                return r;
            }
            r.output = msg + " path=" + rel;
            r.ok = true;
            return r;
        });

    // --- run_shell (C34): workspace cwd; CAP_EXEC; honors g_toolCancelFlag ---
    reg.registerTool(
        "run_shell",
        "Run a short command in the workspace (cmd.exe /c, cancel-aware)",
        R"({"command":{"type":"string","required":true},"timeout_ms":{"type":"integer","default":60000}})",
        CAP_EXEC,
        [&ws](const json& args, const ToolContext& ctx) -> ToolResult {
            ToolResult r;
            r.tool = "run_shell";
            if (ctx.mode && (ctx.mode->caps & CAP_EXEC) == 0) {
                r.denied = true;
                r.output = "DENIED: mode '" + std::string(ctx.mode->name) +
                           "' does not permit run_shell";
                return r;
            }
            std::string cmd = args.value("command", std::string());
            while (!cmd.empty() && (unsigned char)cmd.back() <= ' ') cmd.pop_back();
            if (cmd.empty()) { r.output = "ERROR: command is required"; return r; }
            if (cmd.size() > 2048) {
                r.output = "ERROR: command too long (max 2048)";
                return r;
            }
            const std::string low = toLower(cmd);
            for (const char* bad : {"&&", "||", "|", ";", "`", "$(", "\n", "\r",
                                    "..\\", "../", "rmdir", "del /s", "format ",
                                    "shutdown", "reg add", "reg delete",
                                    ":\\windows"}) {
                if (low.find(bad) != std::string::npos) {
                    r.denied = true;
                    r.output = std::string("DENIED: shell metachar/forbidden: ") + bad;
                    return r;
                }
            }
            int timeout = 60000;
            if (args.contains("timeout_ms")) {
                if (args["timeout_ms"].is_number_integer())
                    timeout = args["timeout_ms"].get<int>();
                else if (args["timeout_ms"].is_string()) {
                    try { timeout = std::stoi(args["timeout_ms"].get<std::string>()); }
                    catch (...) { timeout = 60000; }
                }
            }
            if (timeout < 1000) timeout = 1000;
            if (timeout > 300000) timeout = 300000;
            CommandResult c = runBoundedCommand(cmd, ws.root(),
                                                static_cast<DWORD>(timeout));
            r.output = c.output;
            if (!c.error.empty()) r.output += "\nERROR: " + c.error;
            r.exitCode = static_cast<int>(c.exitCode);
            if (toolCancelRequested()) {
                r.output += "\nCANCELED=1";
                r.ok = false;
                return r;
            }
            r.ok = c.launched && c.completed && c.exitCode == 0;
            if (!c.completed)
                r.output += "\nSHELL_DID_NOT_COMPLETE (timeout/cancel)";
            return r;
        });

    // --- git_diff ---
    reg.registerTool(
        "git_diff", "Show git diff for the workspace",
        R"({})",
        CAP_EXEC,
        [&ws](const json&, const ToolContext&) -> ToolResult {
            ToolResult r;
            r.tool = "git_diff";
            CommandResult c = runBoundedCommand("git diff",
                                                ws.root(), 60000);
            r.output = c.output;
            r.ok = c.launched && c.completed;
            r.exitCode = c.exitCode;
            if (!c.error.empty()) r.output += "\nERROR: " + c.error;
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
    payload["model"] = sanitizeUtf8(model_);
    // Sanitize every message at the serialization boundary. A single stray
    // CP1252 byte anywhere in the conversation (system banner, tool output,
    // task text) used to throw type_error.316 out of payload.dump() and
    // abort the run with exit code 42 instead of reaching the backend.
    json cleanMessages = messages;
    for (auto& m : cleanMessages) {
        if (!m.is_object()) continue;
        for (const char* key : {"role", "content", "name"}) {
            if (m.contains(key) && m[key].is_string())
                m[key] = sanitizeUtf8(m[key].get<std::string>());
        }
    }
    payload["messages"] = std::move(cleanMessages);
    payload["max_tokens"] = maxTokens;
    payload["temperature"] = temperature;
    payload["stream"] = false;

    for (int attempt = 1; attempt <= 3; ++attempt) {
        long status = 0;
        std::string err;
        const std::string body = payload.dump();
        std::string raw = httpPost(path_, body, &status, err);
        if (std::getenv("RAWRXD_HTTP_DEBUG")) {
            std::fprintf(stderr,
                         "[http-debug] POST %s:%d%s model=%s body_bytes=%zu "
                         "status=%ld response_bytes=%zu err=%s\n",
                         "127.0.0.1", port_, path_.c_str(), model_.c_str(),
                         body.size(), status, raw.size(), err.c_str());
            if (!raw.empty())
                std::fprintf(stderr, "[http-debug] response=%s\n",
                             truncateForLedger(raw, 2000).c_str());
        }
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

InferenceResult InferenceClient::completeStream(const std::vector<json>& messages,
                                                int maxTokens, double temperature,
                                                StreamDeltaFn onDelta,
                                                CancelCheckFn shouldCancel) {
    InferenceResult out;
    json payload;
    payload["model"] = sanitizeUtf8(model_);
    json cleanMessages = messages;
    for (auto& m : cleanMessages) {
        if (!m.is_object()) continue;
        for (const char* key : {"role", "content", "name"}) {
            if (m.contains(key) && m[key].is_string())
                m[key] = sanitizeUtf8(m[key].get<std::string>());
        }
    }
    payload["messages"] = std::move(cleanMessages);
    payload["max_tokens"] = maxTokens;
    payload["temperature"] = temperature;
    payload["stream"] = true;
    const std::string body = payload.dump();

    HINTERNET session = WinHttpOpen(L"RawrXDCore/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { out.error = "WinHttpOpen failed"; return out; }
    HINTERNET conn = WinHttpConnect(session, host_.c_str(),
                                    static_cast<INTERNET_PORT>(port_), 0);
    if (!conn) {
        out.error = "WinHttpConnect failed";
        WinHttpCloseHandle(session);
        return out;
    }
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", utf8ToWide(path_).c_str(), nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) {
        out.error = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return out;
    }
    DWORD t = static_cast<DWORD>(timeoutMs_);
    WinHttpSetTimeouts(req, t, t, t, t);
    if (!WinHttpSendRequest(req, L"Content-Type: application/json\r\n", -1L,
                            const_cast<char*>(body.data()),
                            static_cast<DWORD>(body.size()),
                            static_cast<DWORD>(body.size()), 0) ||
        !WinHttpReceiveResponse(req, nullptr)) {
        out.error = "WinHttp stream send/recv failed (" +
                    std::to_string(GetLastError()) + ")";
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return out;
    }
    DWORD code = 0, sz = sizeof(code);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz,
                        WINHTTP_NO_HEADER_INDEX);
    if (code != 200) {
        out.error = "HTTP status " + std::to_string(code);
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return out;
    }

    std::string carry;
    auto ingestLine = [&](const std::string& line) {
        if (line.rfind("data:", 0) != 0) return;
        std::string payload = line.substr(5);
        while (!payload.empty() && (payload.front() == ' ' || payload.front() == '\t'))
            payload.erase(payload.begin());
        if (payload == "[DONE]") {
            out.finishReason = out.finishReason.empty() ? "stop" : out.finishReason;
            return;
        }
        try {
            json doc = json::parse(payload);
            if (!doc.is_object() || !doc.contains("choices") || !doc["choices"].is_array())
                return;
            for (const auto& c : doc["choices"]) {
                if (!c.is_object()) continue;
                if (c.contains("finish_reason") && c["finish_reason"].is_string())
                    out.finishReason = c["finish_reason"].get<std::string>();
                if (!c.contains("delta") || !c["delta"].is_object()) continue;
                const auto& d = c["delta"];
                if (!d.contains("content") || !d["content"].is_string()) continue;
                const std::string piece = d["content"].get<std::string>();
                if (piece.empty()) continue;
                out.content += piece;
                out.streamDeltas += 1;
                out.completionTokens += 1;
                if (onDelta) onDelta(piece);
            }
            if (doc.contains("usage") && doc["usage"].is_object()) {
                out.promptTokens = doc["usage"].value("prompt_tokens", out.promptTokens);
                out.completionTokens =
                    doc["usage"].value("completion_tokens", out.completionTokens);
            }
        } catch (...) {
            /* ignore partial SSE frames */
        }
    };

    for (;;) {
        if (shouldCancel && shouldCancel()) {
            out.canceled = true;
            out.finishReason = "cancelled";
            out.ok = !out.content.empty();
            out.error = out.ok ? std::string() : "cancelled before tokens";
            break;
        }
        DWORD have = 0;
        if (!WinHttpQueryDataAvailable(req, &have)) break;
        if (have == 0) break;
        std::vector<char> buf(static_cast<size_t>(have) + 1, 0);
        DWORD rd = 0;
        if (!WinHttpReadData(req, buf.data(), have, &rd) || rd == 0) break;
        carry.append(buf.data(), rd);
        for (;;) {
            const auto nl = carry.find('\n');
            if (nl == std::string::npos) break;
            std::string line = carry.substr(0, nl);
            carry.erase(0, nl + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) ingestLine(line);
        }
    }
    if (!carry.empty()) ingestLine(carry);
    if (!out.canceled) {
        out.ok = !out.content.empty() || out.finishReason == "stop";
        if (!out.ok && out.error.empty()) out.error = "empty stream";
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return out;
}

}  // namespace rawr
