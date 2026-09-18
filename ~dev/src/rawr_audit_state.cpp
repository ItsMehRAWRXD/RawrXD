// ============================================================================
// rawr_audit_state.cpp — RAWR_AUDIT_STATE_001 implementation.
// Durable audit ledger: deterministic enumeration, candidate review state,
// coverage counters, JSONL persistence.
// ============================================================================
#include "rawr_audit_state.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include "rawr_stub_scan.hpp"

namespace rawrxd {
namespace agent {

namespace {

// FNV-1a 64 over one file's contents (64 KiB chunks). Callers hold the lock.
inline void mixFileContentsLocked(const std::filesystem::path& full,
                                   uint64_t& h) {
    std::ifstream f(full, std::ios::binary);
    if (!f) {
        const char kMissing[] = "<unreadable>";
        for (size_t i = 0; i + 1 < sizeof(kMissing); ++i) {
            h ^= static_cast<unsigned char>(kMissing[i]);
            h *= 1099511628211ull;
        }
        return;
    }
    char buf[64 * 1024];
    while (f.read(buf, sizeof(buf)) || f.gcount()) {
        const size_t n = static_cast<size_t>(f.gcount());
        for (size_t i = 0; i < n; ++i) {
            h ^= static_cast<unsigned char>(buf[i]);
            h *= 1099511628211ull;
        }
        if (!f) break;
    }
}

inline uint64_t fnv1a64Init() { return 1469598103934665603ull; }

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
    generationPath_ = root_ / ".rawr" / "scan_generation.json";
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
    refreshScanEpochLocked();
    persistLocked();
    return counters_.filesEnumerated;
}

// RAWR_STUB_SCAN_001: deterministic scan of every enumerated file.
bool AuditLedger::runSourceScan() {
    std::lock_guard<std::mutex> g(mu_);
    counters_.filesScanned = 0;
    counters_.sourceScanComplete = false;

    refreshScanEpochLocked();
    generation_.epochSchema = kCurrentEpochSchema;
    generation_.epochAlgorithm = kEpochAlgorithm;
    generation_.scanEpoch = scanEpoch_;
    persistGenerationLocked();

    std::vector<ScanCandidate> found;
    for (const auto& rel : enumerated_) {
        std::ifstream f(root_ / rel, std::ios::binary);
        if (!f) continue;  // unreadable: excluded from scan set
        std::string text((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        scanSourceText(rel, text, found);
        ++counters_.filesScanned;
    }

    // Append deduplicated candidates to the ledger (epoch-bound, with the
    // per-file content hash captured at scan time).
    for (const auto& sc : found) {
        bool dup = false;
        for (const auto& existing : candidates_) {
            if (existing.file == sc.file && existing.line == sc.line &&
                existing.scanKind == sc.kind) { dup = true; break; }
        }
        if (dup) continue;
        AuditCandidate c;
        c.id = nextCandidateId_++;
        c.file = sc.file;
        c.line = sc.line;
        c.scanKind = sc.kind;
        c.scanEpoch = scanEpoch_;
        c.sourceFileHash = computeFileHashLocked(sc.file);
        c.evidence = sc.snippet;
        switch (sc.kind) {
            case ScanKind::TodoFixme:        c.type = CandidateType::Todo; break;
            case ScanKind::NotImplemented:   c.type = CandidateType::StubApi; break;
            case ScanKind::AssertFalse:      c.type = CandidateType::Unreachable; break;
            case ScanKind::StubComment:      c.type = CandidateType::StubApi; break;
            case ScanKind::FakeSuccess:      c.type = CandidateType::FakeSuccess; break;
            case ScanKind::DisabledPath:     c.type = CandidateType::DisabledPath; break;
            case ScanKind::StubBody:          c.type = CandidateType::EmptyImpl; break;
            case ScanKind::UnimplementedRef: c.type = CandidateType::StubApi; break;
        }
        candidates_.push_back(c);
    }

    counters_.sourceScanComplete = true;
    persistLocked();
    return true;
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

uint64_t AuditLedger::addScanCandidate(const ScanCandidate& sc) {
    std::lock_guard<std::mutex> g(mu_);
    // Deduplicate: same file+line+kind never enters twice.
    for (const auto& existing : candidates_) {
        if (existing.file == sc.file && existing.line == sc.line &&
            existing.scanKind == sc.kind) {
            return existing.id;
        }
    }
    AuditCandidate c;
    c.id = nextCandidateId_++;
    c.file = sc.file;
    c.line = sc.line;
    c.scanKind = sc.kind;
    c.evidence = sc.snippet;
    switch (sc.kind) {
        case ScanKind::TodoFixme:        c.type = CandidateType::Todo; break;
        case ScanKind::NotImplemented:   c.type = CandidateType::StubApi; break;
        case ScanKind::AssertFalse:      c.type = CandidateType::Unreachable; break;
        case ScanKind::StubComment:      c.type = CandidateType::StubApi; break;
        case ScanKind::FakeSuccess:      c.type = CandidateType::FakeSuccess; break;
        case ScanKind::DisabledPath:     c.type = CandidateType::DisabledPath; break;
        case ScanKind::StubBody:          c.type = CandidateType::EmptyImpl; break;
        case ScanKind::UnimplementedRef: c.type = CandidateType::StubApi; break;
    }
    candidates_.push_back(c);
    return c.id;
}

std::vector<AuditCandidate> AuditLedger::pendingCandidates(uint32_t limit) const {
    std::lock_guard<std::mutex> g(mu_);
    std::vector<AuditCandidate> out;
    out.reserve(std::min<size_t>(limit, candidates_.size()));
    for (const auto& c : candidates_) {
        if (!c.reviewed) {
            out.push_back(c);
            if (out.size() >= limit) break;
        }
    }
    return out;
}

size_t AuditLedger::candidateCount() const {
    std::lock_guard<std::mutex> g(mu_);
    return candidates_.size();
}

bool AuditLedger::reviewCandidate(uint64_t id, const std::string& verdict,
                                  const std::string& note) {
    std::lock_guard<std::mutex> g(mu_);
    for (auto& c : candidates_) {
        if (c.id == id) {
            // Epoch guard: reject reviews of candidates from a scan of a
            // different workspace generation.
            if (!c.scanEpoch.empty() && !scanEpoch_.empty() &&
                c.scanEpoch != scanEpoch_) {
                return false;
            }
            // Per-file freshness guard: the candidate's source file must be
            // byte-identical to scan time, else the review is stale.
            if (c.sourceFileHash != 0) {
                std::error_code ec;
                if (!std::filesystem::exists(root_ / c.file, ec) || ec)
                    return false;
                if (computeFileHashLocked(c.file) != c.sourceFileHash)
                    return false;
            }
            c.reviewed = true;
            c.verdict = verdict;
            c.reviewNote = note;
            persistLocked();
            return true;
        }
    }
    return false;
}

// FNV-1a 64-bit over (relativePath + full file CONTENTS) of the
// enumerated set, in deterministic sorted order. Content-sensitive: any
// in-place edit to any source file changes the epoch. This is a fast
// change detector, NOT cryptographic attestation (receipts label it
// SCAN_CHANGE_HASH / FNV1A64).
std::string AuditLedger::computeScanEpoch() const {
    uint64_t h = 1469598103934665603ull;
    auto mix = [&h](const void* data, size_t n) {
        const auto* p = static_cast<const unsigned char*>(data);
        for (size_t i = 0; i < n; ++i) {
            h ^= p[i];
            h *= 1099511628211ull;
        }
    };
    for (const auto& rel : enumerated_) {  // already sorted
        mix(rel.data(), rel.size());
        mixFileContentsLocked(root_ / rel, h);
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%016llx",
                  static_cast<unsigned long long>(h));
    return std::string(buf);
}

uint64_t AuditLedger::computeFileHash(const std::string& relPath) const {
    std::lock_guard<std::mutex> g(mu_);
    return computeFileHashLocked(relPath);
}

uint64_t AuditLedger::computeFileHashLocked(const std::string& relPath) const {
    uint64_t h = fnv1a64Init();
    mixFileContentsLocked(root_ / relPath, h);
    return h;
}

int AuditLedger::candidateFileFreshness(uint64_t id) const {
    std::lock_guard<std::mutex> g(mu_);
    const AuditCandidate* c = nullptr;
    for (const auto& cand : candidates_)
        if (cand.id == id) { c = &cand; break; }
    if (!c) return 2;
    std::error_code ec;
    if (!std::filesystem::exists(root_ / c->file, ec) || ec) return 2;
    return computeFileHashLocked(c->file) == c->sourceFileHash ? 0 : 1;
}

bool AuditLedger::generationMatchesLive() const {
    std::lock_guard<std::mutex> g(mu_);
    if (generation_.epochSchema != kCurrentEpochSchema) return false;
    if (generation_.epochAlgorithm != kEpochAlgorithm) return false;
    if (generation_.scanEpoch.empty()) return false;
    return generation_.scanEpoch == computeScanEpoch();
}

void AuditLedger::archiveGeneration(const char* reason) {
    std::lock_guard<std::mutex> g(mu_);
    // Preserve the stale generation's evidence verbatim — never rewrite
    // candidate epochs (that would destroy the record that they belonged to
    // a different snapshot).
    std::ostringstream name;
    name << "scan_generation_archived_"
         << (generation_.scanEpoch.empty() ? "none" : generation_.scanEpoch)
         << ".jsonl";
    const std::filesystem::path archivePath =
        root_ / ".rawr" / name.str();
    writeSnapshotLocked(archivePath);
    std::fprintf(stderr,
                 "[RAWR_AUDIT] generation archived reason=%s epoch=%s "
                 "candidates=%zu -> %s\n",
                 reason, generation_.scanEpoch.c_str(), candidates_.size(),
                 archivePath.string().c_str());
    candidates_.clear();
    reviewedFiles_.clear();
    nextCandidateId_ = 1;
    generation_ = ScanGeneration{};
    scanEpoch_.clear();
    counters_ = AuditCounters{};
    std::error_code ec;
    std::filesystem::remove(generationPath_, ec);
}

bool AuditLedger::loadGeneration() {
    std::lock_guard<std::mutex> g(mu_);
    if (candidates_.empty() || generation_.scanEpoch.empty()) return false;
    // Rewrite the generation file + candidates as the durable resume set.
    persistGenerationLocked();
    writeSnapshotLocked(root_ / ".rawr" / "audit_candidates.jsonl");
    return true;
}

void AuditLedger::refreshScanEpoch() {
    std::lock_guard<std::mutex> g(mu_);
    refreshScanEpochLocked();
}

void AuditLedger::refreshScanEpochLocked() {
    scanEpoch_ = computeScanEpoch();
    if (generation_.scanEpoch.empty()) generation_.scanEpoch = scanEpoch_;
    generation_.epochSchema = kCurrentEpochSchema;
    generation_.epochAlgorithm = kEpochAlgorithm;
}

bool AuditLedger::candidateMatchesEpoch(uint64_t id) const {
    std::lock_guard<std::mutex> g(mu_);
    if (scanEpoch_.empty()) return true;
    for (const auto& c : candidates_)
        if (c.id == id)
            return c.scanEpoch.empty() || c.scanEpoch == scanEpoch_;
    return false;
}

void AuditLedger::persistGenerationLocked() {
    std::ofstream out(generationPath_, std::ios::trunc);
    if (!out) return;
    out << "{\n"
        << "  \"epoch_schema\": " << generation_.epochSchema << ",\n"
        << "  \"epoch_algorithm\": \"" << generation_.epochAlgorithm << "\",\n"
        << "  \"scan_epoch\": \"" << generation_.scanEpoch << "\",\n"
        << "  \"source_git_sha\": \"" << generation_.sourceGitSha << "\",\n"
        << "  \"next_candidate_id\": " << nextCandidateId_ << ",\n"
        << "  \"files_enumerated\": " << counters_.filesEnumerated << "\n"
        << "}\n";
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
    return writeSnapshotLocked(jsonlOut);
}

bool AuditLedger::writeSnapshotLocked(
    const std::filesystem::path& jsonlOut) const {
    std::ofstream out(jsonlOut, std::ios::trunc);
    if (!out) return false;

    for (const auto& c : candidates_) {
        out << "{\"event\":\"candidate\",\"id\":" << c.id
            << ",\"file\":\"" << jsonEscape(c.file) << "\""
            << ",\"line\":" << c.line
            << ",\"type\":\"" << candidateTypeName(c.type) << "\""
            << ",\"scan_kind\":\"" << scanKindName(c.scanKind) << "\""
            << ",\"scan_epoch\":\"" << jsonEscape(c.scanEpoch) << "\""
            << ",\"source_file_hash\":\"" << std::hex << c.sourceFileHash
            << std::dec << "\""
            << ",\"reviewed\":" << (c.reviewed ? 1 : 0)
            << ",\"verdict\":\"" << jsonEscape(c.verdict) << "\""
            << ",\"evidence\":\"" << jsonEscape(c.evidence) << "\""
            << ",\"reasoning\":\"" << jsonEscape(c.reasoning) << "\"}\n";
    }
    return true;
}

} // namespace agent
} // namespace rawrxd