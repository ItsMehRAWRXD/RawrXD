// ============================================================================
// rawr_agent_dispatch.cpp — RAWR_AGENT_DISPATCH_001 implementation.
// Read-only tool providers bound to AgentToolRegistry. Arguments arrive as
// simple JSON objects in ToolRequest::stdin_text ({"key":"value"}), matching
// the established headless extractJsonField convention.
// ============================================================================
#include "rawr_agent_dispatch.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>

#include "deep2/AgentToolRegistry.hpp"

namespace rawrxd {
namespace agent {

using RawrXD::Agentic::AgentToolRegistry;
using RawrXD::Agentic::ToolContext;
using RawrXD::Agentic::ToolDescriptor;
using RawrXD::Agentic::ToolRequest;
using RawrXD::Agentic::ToolResult;

namespace {

// Minimal {"key":"value"} extractor — the established convention from
// HeadlessIDE_AutonomousWorkflowMode.cpp. Handles escaped quotes minimally.
std::string jsonField(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    size_t p = json.find(needle);
    if (p == std::string::npos) return {};
    p = json.find(':', p + needle.size());
    if (p == std::string::npos) return {};
    ++p;
    while (p < json.size() && isspace(static_cast<unsigned char>(json[p]))) ++p;
    if (p >= json.size()) return {};
    if (json[p] == '"') {
        ++p;
        std::string out;
        while (p < json.size() && json[p] != '"') {
            if (json[p] == '\\' && p + 1 < json.size()) {
                char n = json[p + 1];
                switch (n) {
                    case 'n':  out += '\n'; break;
                    case 't':  out += '\t'; break;
                    case 'r':  out += '\r'; break;
                    case '\\': out += '\\'; break;
                    case '"':  out += '"';  break;
                    default:   out += n;    break;
                }
                p += 2;
            } else {
                out += json[p++];
            }
        }
        return out;
    }
    // bare word / number
    std::string out;
    while (p < json.size() && json[p] != ',' && json[p] != '}' &&
           !isspace(static_cast<unsigned char>(json[p]))) {
        out += json[p++];
    }
    return out;
}

uint32_t jsonFieldU32(const std::string& json, const std::string& key,
                      uint32_t fallback) {
    const std::string v = jsonField(json, key);
    if (v.empty()) return fallback;
    try { return static_cast<uint32_t>(std::stoul(v)); }
    catch (...) { return fallback; }
}

CandidateType candidateTypeFromName(const std::string& name) {
    if (name == "todo_fixme")            return CandidateType::Todo;
    if (name == "empty_implementation")  return CandidateType::EmptyImpl;
    if (name == "fake_success_path")      return CandidateType::FakeSuccess;
    if (name == "disabled_production_path") return CandidateType::DisabledPath;
    if (name == "unreachable_feature")   return CandidateType::Unreachable;
    if (name == "stub_api")               return CandidateType::StubApi;
    return CandidateType::Other;
}

// ---------------------------------------------------------------------------
// Tool providers
// ---------------------------------------------------------------------------

// workspace.list — recursive listing of the audit universe (relative paths,
// newline-separated, capped for context economy).
ToolResult toolWorkspaceList(const ToolRequest& req, AuditLedger* ledger) {
    ToolResult r;
    if (!ledger) { r.exit_code = 1; r.stderr_text = "no ledger"; return r; }

    const auto& files = ledger->enumeratedFiles();
    uint32_t limit = jsonFieldU32(req.stdin_text, "limit", 2000);
    std::string out;
    out.reserve(files.size() * 32);
    size_t n = 0;
    for (const auto& f : files) {
        if (n++ >= limit) { out += "...(" + std::to_string(files.size()) +
                                  " total, use code.search to filter)\n"; break; }
        out += f;
        out += '\n';
    }
    r.stdout_text = std::move(out);
    return r;
}

// file.read — bounded read with line numbers, [start,end] 1-based inclusive.
ToolResult toolFileRead(const ToolRequest& req, AuditLedger* ledger) {
    ToolResult r;
    if (!ledger) { r.exit_code = 1; r.stderr_text = "no ledger"; return r; }

    const std::string rel = jsonField(req.stdin_text, "path");
    if (rel.empty()) { r.exit_code = 64; r.stderr_text = "missing path"; return r; }
    if (rel.find("..") != std::string::npos) {
        r.exit_code = 77; r.stderr_text = "path escape rejected"; return r;
    }

    std::filesystem::path full = ledger->workspaceRoot() / rel;
    std::ifstream f(full, std::ios::binary);
    if (!f) { r.exit_code = 66; r.stderr_text = "cannot open " + rel; return r; }

    const uint32_t start = jsonFieldU32(req.stdin_text, "start", 1);
    const uint32_t end   = jsonFieldU32(req.stdin_text, "end", start + 199);
    const uint32_t maxLines = 400;

    std::string out;
    std::string line;
    uint32_t no = 0;
    char buf[8192];
    while (f.good() && no < end && no < start + maxLines) {
        f.getline(buf, sizeof(buf));
        ++no;
        if (no < start) continue;
        out += std::to_string(no);
        out += '|';
        out += buf;
        out += '\n';
    }
    if (out.empty()) { r.exit_code = 1; r.stderr_text = "range empty"; return r; }
    r.stdout_text = std::move(out);
    return r;
}

// code.search — regex-lite: literal substring search across the enumerated
// universe; returns file:line:text hits, capped.
ToolResult toolCodeSearch(const ToolRequest& req, AuditLedger* ledger) {
    ToolResult r;
    if (!ledger) { r.exit_code = 1; r.stderr_text = "no ledger"; return r; }

    const std::string needle = jsonField(req.stdin_text, "query");
    if (needle.empty()) { r.exit_code = 64; r.stderr_text = "missing query"; return r; }
    uint32_t maxHits = jsonFieldU32(req.stdin_text, "max_hits", 50);

    std::string out;
    uint32_t hits = 0;
    for (const auto& rel : ledger->enumeratedFiles()) {
        if (hits >= maxHits) break;
        std::ifstream f(ledger->workspaceRoot() / rel, std::ios::binary);
        if (!f) continue;
        std::string line;
        uint32_t no = 0;
        char buf[16384];
        while (f.good() && hits < maxHits) {
            f.getline(buf, sizeof(buf));
            ++no;
            if (std::strstr(buf, needle.c_str()) != nullptr) {
                out += rel + ":" + std::to_string(no) + ": " + buf + "\n";
                ++hits;
            }
        }
    }
    if (out.empty()) r.stdout_text = "(no hits)";
    else r.stdout_text = std::move(out);
    return r;
}

// symbol.find / symbol.references — token-level symbol scan. First drop is a
// shared literal matcher (no ctags dependency); adequate for audit flows.
ToolResult toolSymbolFind(const ToolRequest& req, AuditLedger* ledger,
                          bool referencesOnly) {
    ToolResult r;
    if (!ledger) { r.exit_code = 1; r.stderr_text = "no ledger"; return r; }

    const std::string sym = jsonField(req.stdin_text, "symbol");
    if (sym.empty()) { r.exit_code = 64; r.stderr_text = "missing symbol"; return r; }
    uint32_t maxHits = jsonFieldU32(req.stdin_text, "max_hits", 50);

    auto isIdent = [&](const std::string& s) {
        for (char c : s)
            if (!isalnum(static_cast<unsigned char>(c)) && c != '_') return false;
        return !s.empty();
    };
    (void)isIdent;

    std::string out;
    uint32_t hits = 0;
    for (const auto& rel : ledger->enumeratedFiles()) {
        if (hits >= maxHits) break;
        std::ifstream f(ledger->workspaceRoot() / rel, std::ios::binary);
        if (!f) continue;
        std::string line;
        uint32_t no = 0;
        char buf[16384];
        while (f.good() && hits < maxHits) {
            f.getline(buf, sizeof(buf));
            ++no;
            char* p = std::strstr(buf, sym.c_str());
            if (!p) continue;
            // word-boundary check
            const bool lo = p == buf ||
                             !isalnum(static_cast<unsigned char>(p[-1]));
            const char after = p[sym.size()];
            const bool hi = after == '\0' ||
                            !isalnum(static_cast<unsigned char>(after));
            if (!lo || !hi) continue;
            if (referencesOnly && std::strstr(buf, "::") != nullptr &&
                p > buf && p[-1] == ':') {
                // still a reference for our purposes
            }
            out += rel + ":" + std::to_string(no) + ": " + buf + "\n";
            ++hits;
        }
    }
    if (out.empty()) r.stdout_text = "(no hits)";
    else r.stdout_text = std::move(out);
    return r;
}

// git.status / git.diff — shelling out to git with output captured; read-only.
ToolResult toolGit(const ToolRequest& req, AuditLedger* ledger, bool diff) {
    ToolResult r;
    if (!ledger) { r.exit_code = 1; r.stderr_text = "no ledger"; return r; }

    const std::string git = "C:\\Program Files\\Git\\cmd\\git.exe";
    std::string cmd = "\"" + git + "\" -C \"" +
                      ledger->workspaceRoot().string() + "\" ";
    cmd += diff ? "diff --stat" : "status --short";

#ifdef _WIN32
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe) { r.exit_code = 1; r.stderr_text = "git spawn failed"; return r; }
    std::string out;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe)) {
        out += buf;
        if (out.size() > 65536) { out += "\n[truncated]"; break; }
    }
#ifdef _WIN32
    const int ec = _pclose(pipe);
#else
    const int ec = pclose(pipe);
#endif
    r.exit_code = ec;
    if (ec == 0) r.stdout_text = std::move(out);
    else r.stderr_text = std::move(out);
    return r;
}

// build.target / test.run — invoke cmake for the rawr_monolith build tree.
ToolResult toolBuildTarget(const ToolRequest& req, AuditLedger* ledger,
                           bool tests) {
    ToolResult r;
    if (!ledger) { r.exit_code = 1; r.stderr_text = "no ledger"; return r; }

    const std::string target = jsonField(req.stdin_text, "target");
    const std::string buildDir =
        (ledger->workspaceRoot() / "build_p2").string();

    std::string cmd;
    if (tests) {
        cmd = "cmake --build \"" + buildDir + "\" --config Release --target " +
              (target.empty() ? "k2_smoke_test" : target) +
              " && \"" + buildDir + "\\Release\\" +
              (target.empty() ? "k2_smoke_test" : target) + ".exe\"";
    } else {
        cmd = "cmake --build \"" + buildDir + "\" --config Release --target " +
              (target.empty() ? "rawr_monolith" : target);
    }

#ifdef _WIN32
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe) { r.exit_code = 1; r.stderr_text = "spawn failed"; return r; }
    std::string out;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe)) {
        out += buf;
        if (out.size() > 262144) { out += "\n[truncated]"; break; }
    }
#ifdef _WIN32
    const int ec = _pclose(pipe);
#else
    const int ec = pclose(pipe);
#endif
    r.exit_code = ec;
    if (ec == 0) r.stdout_text = std::move(out);
    else { r.stderr_text = out.substr(0, 8192); r.stdout_text = out; }
    return r;
}

// ---------------------------------------------------------------------------
// audit.* ledger tools — the model's only write surface (runtime-owned).
// ---------------------------------------------------------------------------

ToolResult toolAuditAddCandidate(const ToolRequest& req, AuditLedger* ledger) {
    ToolResult r;
    if (!ledger) { r.exit_code = 1; r.stderr_text = "no ledger"; return r; }
    const std::string file = jsonField(req.stdin_text, "file");
    if (file.empty()) { r.exit_code = 64; r.stderr_text = "missing file"; return r; }
    const uint32_t line = jsonFieldU32(req.stdin_text, "line", 0);
    const std::string typeName = jsonField(req.stdin_text, "type");
    const std::string evidence = jsonField(req.stdin_text, "evidence");
    const std::string reasoning = jsonField(req.stdin_text, "reasoning");
    const uint64_t id = ledger->addCandidate(
        file, line, candidateTypeFromName(typeName), evidence, reasoning);
    r.stdout_text = "candidate_id=" + std::to_string(id);
    return r;
}

ToolResult toolAuditReview(const ToolRequest& req, AuditLedger* ledger) {
    ToolResult r;
    if (!ledger) { r.exit_code = 1; r.stderr_text = "no ledger"; return r; }
    const uint32_t id = jsonFieldU32(req.stdin_text, "id", 0);
    if (id == 0) { r.exit_code = 64; r.stderr_text = "missing id"; return r; }
    const std::string verdict = jsonField(req.stdin_text, "verdict");
    const std::string note = jsonField(req.stdin_text, "note");
    if (!ledger->reviewCandidate(id, verdict, note)) {
        r.exit_code = 1; r.stderr_text = "candidate not found"; return r;
    }
    r.stdout_text = "reviewed=" + std::to_string(id);
    return r;
}

ToolResult toolAuditFilesReviewed(const ToolRequest& req, AuditLedger* ledger) {
    ToolResult r;
    if (!ledger) { r.exit_code = 1; r.stderr_text = "no ledger"; return r; }
    // Accepts {"files":"a.cpp b.cpp"} or {"file":"a.cpp"}.
    std::vector<std::string> files;
    std::string one = jsonField(req.stdin_text, "file");
    std::string many = jsonField(req.stdin_text, "files");
    std::istringstream ss(many.empty() ? one : many);
    std::string tok;
    while (ss >> tok) files.push_back(tok);
    if (files.empty()) { r.exit_code = 64; r.stderr_text = "missing files"; return r; }
    ledger->markFilesReviewed(files);
    r.stdout_text = "marked=" + std::to_string(files.size());
    return r;
}

ToolResult toolAuditCoverage(const ToolRequest& req, AuditLedger* ledger) {
    (void)req;
    ToolResult r;
    if (!ledger) { r.exit_code = 1; r.stderr_text = "no ledger"; return r; }
    const AuditCounters c = ledger->counters();
    std::ostringstream out;
    out << "FILES_TOTAL=" << c.filesTotal
        << "\nFILES_ENUMERATED=" << c.filesEnumerated
        << "\nFILES_REVIEWED=" << c.filesReviewed
        << "\nCANDIDATES_TOTAL=" << c.candidatesTotal
        << "\nCANDIDATES_REVIEWED=" << c.candidatesReviewed
        << "\nCANDIDATES_PENDING=" << c.candidatesPending
        << "\nTOOL_FAILURES=" << c.toolFailures
        << "\nMODEL_FALLBACKS=" << c.modelFallbacks
        << "\nCOVERAGE_COMPLETE=" << (ledger->coverageComplete() ? 1 : 0);
    r.stdout_text = out.str();
    return r;
}

} // namespace

// ---------------------------------------------------------------------------
// Registration — binds the read-only audit tool set onto the authority.
// ---------------------------------------------------------------------------
void registerAuditToolProviders(AgentToolRegistry& authority,
                               AuditLedger* ledger) {
    auto reg = [&authority, ledger](ToolDescriptor d, AgentToolRegistry::Handler h) {
        if (authority.contains(d.id)) return;
        try { authority.registerTool(std::move(d), std::move(h)); }
        catch (const std::invalid_argument&) { /* duplicate race */ }
    };

    reg({"workspace.list", {"list_workspace"}, "List audit-universe files."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolWorkspaceList(q, ledger); });
    reg({"file.read", {"read_file"}, "Read file lines with line numbers."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolFileRead(q, ledger); });
    reg({"code.search", {"search_code"}, "Substring search across sources."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolCodeSearch(q, ledger); });
    reg({"symbol.find", {"find_symbol"}, "Find symbol occurrences."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolSymbolFind(q, ledger, false); });
    reg({"symbol.references", {"ref_symbol"}, "Find symbol references."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolSymbolFind(q, ledger, true); });
    reg({"git.status", {"status_git"}, "Git status of workspace."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolGit(q, ledger, false); });
    reg({"git.diff", {"diff_git"}, "Git diff of workspace."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolGit(q, ledger, true); });
    reg({"build.target", {"build"}, "Build a CMake target."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolBuildTarget(q, ledger, false); });
    reg({"test.run", {"run_test"}, "Build+run a test executable."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolBuildTarget(q, ledger, true); });

    // audit.* — ledger transitions (the only mutable surface; runtime-owned)
    reg({"audit.add_candidate", {"add_candidate"}, "Record audit candidate."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolAuditAddCandidate(q, ledger); });
    reg({"audit.review", {"review_candidate"}, "Mark candidate reviewed."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolAuditReview(q, ledger); });
    reg({"audit.files_reviewed", {"files_reviewed"}, "Mark files reviewed."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolAuditFilesReviewed(q, ledger); });
    reg({"audit.coverage", {"coverage"}, "Coverage counters."},
        [ledger](const ToolRequest& q, ToolContext&) { return toolAuditCoverage(q, ledger); });
}

std::string agentToolCatalogJson() {
    return
        "TOOLS (read-only audit authority):\n"
        "- workspace.list {\"limit\":N} — list audit-universe files\n"
        "- file.read {\"path\":\"rel.cpp\",\"start\":1,\"end\":200} — read lines\n"
        "- code.search {\"query\":\"...\",\"max_hits\":N} — substring search\n"
        "- symbol.find {\"symbol\":\"name\"} — occurrences\n"
        "- symbol.references {\"symbol\":\"name\"} — reference scan\n"
        "- git.status / git.diff — repository state\n"
        "- build.target {\"target\":\"rawr_monolith\"} — build\n"
        "- test.run {\"target\":\"k2_smoke_test\"} — build+run test\n"
        "AUDIT LEDGER (record findings; runtime owns completion):\n"
        "- audit.add_candidate {\"file\":\"..\",\"line\":N,\"type\":\"todo_fixme|empty_implementation|fake_success_path|disabled_production_path|unreachable_feature|stub_api|other\",\"evidence\":\"..\",\"reasoning\":\"..\"}\n"
        "- audit.review {\"id\":N,\"verdict\":\"confirmed|false_positive|needs_runtime_proof\",\"note\":\"..\"}\n"
        "- audit.files_reviewed {\"files\":\"a.cpp b.cpp\"} — mark files fully reviewed\n"
        "- audit.coverage {} — coverage counters\n";
}

} // namespace agent
} // namespace rawrxd