// ============================================================================
// rawr_audit_state.cpp — RAWR_AUDIT_STATE_001 implementation.
// Durable audit ledger: deterministic enumeration, candidate review state,
// coverage counters, JSONL persistence.
// ============================================================================
#include "rawr_audit_state.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>

namespace rawrxd {
namespace agent {

namespace {

// Ignore/exclusion policy — deterministic, no configuration drift.
bool isExcludedDirName(const std::string& name) {
    static const char* kExcluded[] = {
        ".git", ".rawr", "build", "build_p1", "build_p2", "build_p3",
        "build_ninja", "build-ninja", "build_win32ide", "build_p1pra_win32ide",
        "build_p2", "build_win32ide-fresh", "build-absolutely-final",
        "_deps", "node_modules", "__pycache__", "Debug", "Release",
        "x64", ".vs", ".vscode", ".worktrees", ".cursor", "evidence",
        nullptr
    };
    for (int i = 0; kExcluded[i]; ++i)
        if (name == kExcluded[i]) return true;
    return false;
}

bool isSourceExtension(const std::string& ext) {
    static const char* kExts[] = {
        ".cpp", ".cxx", ".cc", ".c", ".h", ".hpp", ".hh", ".hxx",
        ".inl", ".asm", ".S", ".cmake", ".txt", ".md", ".json",
        ".py", ".natvis", ".yml", ".yaml", ".sh", ".ps1", nullptr
    };
    for (int i = 0; kExts[i]; ++i)
        if (ext == kExts[i]) return true;
    return false;
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

} // namespace

AuditLedger::AuditLedger(std::filesystem::path workspaceRoot)
    : root_(std::move(workspaceRoot)) {
    std::error_code ec;
    std::filesystem::create_directories(root_ / ".rawr", ec);
    statePath_ = root_ / ".rawr" / "audit_state.jsonl";
}

// Deterministic source enumeration. Idempotent: repeated calls do not grow
// the file set. Excluded directories never enter the audit universe.
uint64_t AuditLedger::enumerateSources() {
    std::lock_guard<std::mutex> g(mu_);
    enumerated_.clear();
    counters_.filesEnumerated = 0;

    std::vector<std::filesystem::path> stack;
    stack.push_back(root_);

    while (!stack.empty()) {
        const std::filesystem::path dir = stack.back();
        stack.pop_back();

        std::error_code ec;
        std::vector<std::string> names;
        for (auto it = std::filesystem::directory_iterator(dir, ec);
             it != std::filesystem::directory_iterator(); it.increment(ec)) {
            if (ec) break;
            names.push_back(it->path().filename().string());
        }
        std::sort(names.begin(), names.end());

        for (const auto& name : names) {
            const std::filesystem::path full = dir / name;
            if (std::filesystem::is_directory(full, ec)) {
                if (!isExcludedDirName(name)) stack.push_back(full);
                else counters_.filesExcluded++;  // approximate dir count
                continue;
            }
            if (!isSourceExtension(full.extension().string())) continue;
            enumerated_.push_back(std::filesystem::relative(full, root_)
                                      .generic_string());
        }
    }

    std::sort(enumerated_.begin(), enumerated_.end());
    counters_.filesTotal      = enumerated_.size();
    counters_.filesEnumerated = enumerated_.size();
    persistLocked();
    return counters_.filesEnumerated;
}

uint64_t AuditLedger::addCandidate(const std::string& file, uint32_t line,
                                   CandidateType type,
                                   const std::string& evidence,
                                   const std::string& reasoning) {
    std::lock_guard<std::mutex> g(mu_);
    AuditCandidate c;
    c.id = nextCandidateId_++;
    c.file = file;
    c.line = line;
    c.type = type;
    c.evidence = evidence;
    c.reasoning = reasoning;
    candidates_.push_back(c);
    persistLocked();
    return c.id;
}

bool AuditLedger::reviewCandidate(uint64_t id, const std::string& verdict,
                                  const std::string& note) {
    std::lock_guard<std::mutex> g(mu_);
    for (auto& c : candidates_) {
        if (c.id == id) {
            c.reviewed = true;
            c.verdict = verdict;
            c.reviewNote = note;
            persistLocked();
            return true;
        }
    }
    return false;
}

bool AuditLedger::markFilesReviewed(const std::vector<std::string>& files) {
    std::lock_guard<std::mutex> g(mu_);
    for (const auto& f : files) {
        if (!f.empty()) reviewedFiles_.insert(f);
    }
    persistLocked();
    return true;
}

void AuditLedger::persistLocked() {
    std::ofstream out(statePath_, std::ios::app);
    if (!out) return;

    AuditCounters c = counters_;
    c.candidatesTotal    = candidates_.size();
    c.candidatesReviewed = 0;
    for (const auto& cand : candidates_)
        if (cand.reviewed) ++c.candidatesReviewed;
    c.candidatesPending = c.candidatesTotal - c.candidatesReviewed;
    c.filesReviewed     = reviewedFiles_.size();

    out << "{\"event\":\"state\",\"files_total\":" << c.filesTotal
        << ",\"files_enumerated\":" << c.filesEnumerated
        << ",\"files_reviewed\":" << c.filesReviewed
        << ",\"files_excluded\":" << c.filesExcluded
        << ",\"candidates_total\":" << c.candidatesTotal
        << ",\"candidates_reviewed\":" << c.candidatesReviewed
        << ",\"candidates_pending\":" << c.candidatesPending
        << ",\"tool_failures\":" << c.toolFailures
        << ",\"model_fallbacks\":" << c.modelFallbacks << "}\n";
}

bool AuditLedger::writeSnapshot(const std::filesystem::path& jsonlOut) const {
    std::lock_guard<std::mutex> g(mu_);
    std::ofstream out(jsonlOut, std::ios::trunc);
    if (!out) return false;

    for (const auto& c : candidates_) {
        out << "{\"event\":\"candidate\",\"id\":" << c.id
            << ",\"file\":\"" << jsonEscape(c.file) << "\""
            << ",\"line\":" << c.line
            << ",\"type\":\"" << candidateTypeName(c.type) << "\""
            << ",\"reviewed\":" << (c.reviewed ? 1 : 0)
            << ",\"verdict\":\"" << jsonEscape(c.verdict) << "\""
            << ",\"evidence\":\"" << jsonEscape(c.evidence) << "\""
            << ",\"reasoning\":\"" << jsonEscape(c.reasoning) << "\"}\n";
    }
    return true;
}

} // namespace agent
} // namespace rawrxd