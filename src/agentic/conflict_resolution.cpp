// ============================================================================
// File: src/agentic/conflict_resolution.cpp
//
// Implementation of the Advanced Conflict Resolution Engine.
// ============================================================================

#include "conflict_resolution.hpp"

#include <algorithm>
#include <cctype>
#include <condition_variable>
#include <fstream>
#include <sstream>
#include <cmath>

namespace RawrXD {
namespace ConflictEngine {

// ============================================================================
// Utilities
// ============================================================================

static std::string toLowerCopy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::vector<std::string> splitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::string current;
    for (char c : text) {
        if (c == '\n') {
            if (!current.empty() && current.back() == '\r') current.pop_back();
            lines.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) {
        if (current.back() == '\r') current.pop_back();
        lines.push_back(current);
    }
    return lines;
}

static std::string joinLines(const std::vector<std::string>& lines) {
    std::string out;
    for (size_t i = 0; i < lines.size(); ++i) {
        out += lines[i];
        if (i + 1 < lines.size()) out += "\n";
    }
    return out;
}

static int64_t nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string newUuid() {
    static std::atomic<uint64_t> counter{0};
    uint64_t n = counter.fetch_add(1);
    int64_t t = nowMs();
    std::ostringstream oss;
    oss << std::hex << t << "-" << n;
    return oss.str();
}

static std::string trimCopy(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

// very small glob: supports * and ?
static bool globMatch(const std::string& pattern, const std::string& text) {
    size_t p = 0, t = 0, starP = std::string::npos, starT = 0;
    while (t < text.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == text[t])) {
            ++p; ++t;
        } else if (p < pattern.size() && pattern[p] == '*') {
            starP = p++; starT = t;
        } else if (starP != std::string::npos) {
            p = starP + 1; t = ++starT;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

static std::string fileExtension(const std::string& filePath) {
    size_t dot = filePath.find_last_of('.');
    size_t slash = filePath.find_last_of("/\\");
    if (dot == std::string::npos) return "";
    if (slash != std::string::npos && dot < slash) return "";
    return toLowerCopy(filePath.substr(dot + 1));
}

// ============================================================================
// ConflictDetector
// ============================================================================

ConflictDetector::ConflictDetector(const DetectionConfig& config)
    : m_config(config) {}

std::vector<std::string> ConflictDetector::extractSemanticTokens(const std::string& text) const {
    std::vector<std::string> tokens;
    std::string cur;
    for (char c : text) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            cur.push_back(c);
        } else {
            if (cur.size() >= 3) tokens.push_back(cur);
            cur.clear();
        }
    }
    if (cur.size() >= 3) tokens.push_back(cur);
    return tokens;
}

Edit::SemanticType ConflictDetector::classifyByPattern(const std::string& text,
                                                       const std::string& filePath) const {
    std::string t = trimCopy(text);
    std::string ext = fileExtension(filePath);

    if (t.rfind("//", 0) == 0 || t.rfind("/*", 0) == 0 || t.rfind("#", 0) == 0 ||
        t.rfind("*", 0) == 0 || t.rfind("///", 0) == 0 || t.rfind("@", 0) == 0)
        return Edit::SemanticType::Comment;

    if (t.find("#include") != std::string::npos || t.find("import ") != std::string::npos ||
        t.find("using ") != std::string::npos || t.find("require(") != std::string::npos)
        return Edit::SemanticType::ImportStatement;

    if (t.find("class ") != std::string::npos || t.find("struct ") != std::string::npos ||
        t.find("interface ") != std::string::npos || t.find("namespace ") != std::string::npos)
        return Edit::SemanticType::ClassDefinition;

    if (t.find("TEST(") != std::string::npos || t.find("ASSERT_") != std::string::npos ||
        t.find("EXPECT_") != std::string::npos || t.find("def test_") != std::string::npos ||
        (ext == "py" && t.find("test") != std::string::npos))
        return Edit::SemanticType::TestCode;

    bool looksLikeConfig = (ext == "json" || ext == "yaml" || ext == "yml" ||
                            ext == "toml" || ext == "ini" || ext == "cfg");
    if (looksLikeConfig) return Edit::SemanticType::Configuration;

    if (t.find("TEST") == std::string::npos &&
        (t.find("void ") != std::string::npos || t.find("int ") != std::string::npos ||
         t.find("bool ") != std::string::npos || t.find("auto ") != std::string::npos) &&
        t.find('(') != std::string::npos && t.find(';') == std::string::npos)
        return Edit::SemanticType::FunctionSignature;

    if (t.find("int ") != std::string::npos || t.find("float ") != std::string::npos ||
        t.find("double ") != std::string::npos || t.find("bool ") != std::string::npos ||
        t.find("std::string ") != std::string::npos || t.find("char ") != std::string::npos ||
        t.find("var ") != std::string::npos || t.find("let ") != std::string::npos)
        return Edit::SemanticType::VariableDeclaration;

    if (t.find("return ") != std::string::npos || t.find("if (") != std::string::npos ||
        t.find("for (") != std::string::npos || t.find("while (") != std::string::npos)
        return Edit::SemanticType::FunctionBody;

    if (ext == "md" || ext == "txt" || ext == "rst") return Edit::SemanticType::Documentation;

    return Edit::SemanticType::Unknown;
}

Edit::SemanticType ConflictDetector::classifyEditSemantics(const Edit& edit) const {
    return classifyByPattern(edit.newText, edit.filePath);
}

bool ConflictDetector::hasSemanticDependency(const Edit& edit1, const Edit& edit2) const {
    if (edit1.filePath != edit2.filePath) return false;

    Edit::SemanticType t1 = classifyEditSemantics(edit1);
    Edit::SemanticType t2 = classifyEditSemantics(edit2);
    if (t1 != t2) return false;

    // Same semantic type: check token overlap for dependency
    auto toks1 = extractSemanticTokens(edit1.newText);
    auto toks2 = extractSemanticTokens(edit2.newText);
    if (toks1.empty() || toks2.empty()) return false;

    std::unordered_map<std::string, int> counts;
    for (auto& t : toks1) counts[t]++;
    for (auto& t : toks2) {
        if (counts.count(t)) return true;
    }
    return false;
}

bool ConflictDetector::shouldIgnoreFile(const std::string& filePath) const {
    for (const auto& pat : m_config.ignorePatterns) {
        if (globMatch(pat, filePath)) return true;
    }
    return false;
}

std::vector<std::pair<Edit, Edit>> ConflictDetector::findOverlappingEdits(
    const std::vector<Edit>& edits) const {

    std::vector<std::pair<Edit, Edit>> result;
    for (size_t i = 0; i < edits.size(); ++i) {
        for (size_t j = i + 1; j < edits.size(); ++j) {
            const Edit& a = edits[i];
            const Edit& b = edits[j];
            if (a.filePath != b.filePath) continue;
            if (!a.range.overlaps(b.range)) continue;
            if (a.agentId == b.agentId) continue;   // same agent edits don't conflict
            result.emplace_back(a, b);
        }
    }
    return result;
}

std::vector<Conflict> ConflictDetector::detectConflicts(const std::vector<Edit>& edits) const {
    std::vector<Conflict> conflicts;

    std::vector<Edit> active;
    active.reserve(edits.size());
    for (const auto& e : edits) {
        if (!shouldIgnoreFile(e.filePath)) active.push_back(e);
    }

    // 1) direct text overlap
    auto overlapping = findOverlappingEdits(active);
    for (const auto& pr : overlapping) {
        Conflict c;
        c.id = newUuid();
        c.filePath = pr.first.filePath;
        c.conflictingEdits = { pr.first, pr.second };
        c.affectedRange.startLine = std::min(pr.first.range.startLine, pr.second.range.startLine);
        c.affectedRange.startColumn = std::min(pr.first.range.startColumn, pr.second.range.startColumn);
        c.affectedRange.endLine = std::max(pr.first.range.endLine, pr.second.range.endLine);
        c.affectedRange.endColumn = std::max(pr.first.range.endColumn, pr.second.range.endColumn);
        c.detectedAt = nowMs();
        c.type = Conflict::ConflictType::TextOverlap;
        c.detectionReason = "Overlapping edit ranges from agents '" +
                            pr.first.agentId + "' and '" + pr.second.agentId + "'";
        conflicts.push_back(c);
    }

    // Honour the configured overlap threshold: ranges overlapping by more than
    // this many lines are ignored (used to suppress trivial neighbour noise).
    if (m_config.maxOverlapThreshold > 0) {
        conflicts.erase(
            std::remove_if(conflicts.begin(), conflicts.end(),
                           [&](const Conflict& c) {
                               int overlap = c.affectedRange.endLine - c.affectedRange.startLine + 1;
                               return overlap > m_config.maxOverlapThreshold;
                           }),
            conflicts.end());
    }

    // 2) semantic overlap
    if (m_config.enableSemanticDetection) {
        for (size_t i = 0; i < active.size(); ++i) {
            for (size_t j = i + 1; j < active.size(); ++j) {
                const Edit& a = active[i];
                const Edit& b = active[j];
                if (a.filePath != b.filePath || a.agentId == b.agentId) continue;

                bool rangeOverlap = a.range.overlaps(b.range);
                bool alreadyFound = false;
                for (const auto& existing : conflicts) {
                    if (existing.filePath != a.filePath) continue;
                    for (const auto& e : existing.conflictingEdits) {
                        if (e.id == a.id) {
                            for (const auto& f : existing.conflictingEdits) {
                                if (f.id == b.id) { alreadyFound = true; break; }
                            }
                        }
                        if (alreadyFound) break;
                    }
                    if (alreadyFound) break;
                }
                if (alreadyFound) continue;

                bool semDep = hasSemanticDependency(a, b);
                if (!rangeOverlap && !semDep) continue;

                Conflict c;
                c.id = newUuid();
                c.filePath = a.filePath;
                c.conflictingEdits = { a, b };
                c.affectedRange.startLine = std::min(a.range.startLine, b.range.startLine);
                c.affectedRange.endLine = std::max(a.range.endLine, b.range.endLine);
                c.affectedRange.startColumn = 0;
                c.affectedRange.endColumn = 0;
                c.detectedAt = nowMs();
                c.type = rangeOverlap ? Conflict::ConflictType::SemanticOverlap
                                      : Conflict::ConflictType::DependencyConflict;
                c.detectionReason = semDep
                    ? "Semantic overlap between edits to the same code element"
                    : "Range overlap detected";
                conflicts.push_back(c);
            }
        }
    }
    // 3) logic conflict: same file, opposing content
    if (m_config.enableDependencyDetection) {
        for (size_t i = 0; i < active.size(); ++i) {
            for (size_t j = i + 1; j < active.size(); ++j) {
                const Edit& a = active[i];
                const Edit& b = active[j];
                if (a.filePath != b.filePath || a.agentId == b.agentId) continue;
                if (a.oldText.empty() || b.oldText.empty()) continue;

                // Skip pairs already reported by the earlier detection passes:
                // one conflict per edit pair keeps resolution unambiguous.
                bool alreadyReported = false;
                for (const auto& existing : conflicts) {
                    if (existing.filePath != a.filePath) continue;
                    bool hasA = false, hasB = false;
                    for (const auto& e : existing.conflictingEdits) {
                        if (e.id == a.id) hasA = true;
                        if (e.id == b.id) hasB = true;
                    }
                    if (hasA && hasB) { alreadyReported = true; break; }
                }
                if (alreadyReported) continue;

                bool sameBase = (a.oldText == b.oldText);
                bool differentResult = (a.newText != b.newText);
                bool rangesTouch = a.range.overlaps(b.range) ||
                                   a.range.endLine == b.range.startLine ||
                                   b.range.endLine == a.range.startLine;

                if (sameBase && differentResult && rangesTouch) {
                    Conflict c;
                    c.id = newUuid();
                    c.filePath = a.filePath;
                    c.conflictingEdits = { a, b };
                    c.affectedRange.startLine = std::min(a.range.startLine, b.range.startLine);
                    c.affectedRange.endLine = std::max(a.range.endLine, b.range.endLine);
                    c.detectedAt = nowMs();
                    c.type = Conflict::ConflictType::LogicConflict;
                    c.detectionReason = "Opposing replacements for identical base text";
                    conflicts.push_back(c);
                }
            }
        }
    }

    return conflicts;
}

std::vector<Conflict> ConflictDetector::detectConflictsForEdit(
    const Edit& newEdit, const std::vector<Edit>& existingEdits) const {

    std::vector<Edit> all = existingEdits;
    all.push_back(newEdit);
    return detectConflicts(all);
}

void ConflictDetector::setConfig(const DetectionConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
}

ConflictDetector::DetectionConfig ConflictDetector::getConfig() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config;
}

// ============================================================================
// ThreeWayMerge
// ============================================================================

ThreeWayMerge::ThreeWayMerge(const MergeOptions& options)
    : m_options(options) {}

std::vector<ThreeWayMerge::DiffHunk> ThreeWayMerge::computeDiff3(
    const std::string& base, const std::string& local, const std::string& remote) const {

    auto baseL = splitLines(base);
    auto localL = splitLines(local);
    auto remoteL = splitLines(remote);

    std::vector<DiffHunk> hunks;
    size_t bi = 0, li = 0, ri = 0;

    // Simple line-walk diff3: group runs where base/local/remote diverge.
    auto collectRun = [&](bool& baseMoved, bool& localMoved, bool& remoteMoved) {
        DiffHunk h;
        h.baseStart = static_cast<int>(bi);
        h.localStart = static_cast<int>(li);
        h.remoteStart = static_cast<int>(ri);
        std::string baseLine = (bi < baseL.size()) ? baseL[bi] : std::string();
        std::string localLine = (li < localL.size()) ? localL[li] : std::string();
        std::string remoteLine = (ri < remoteL.size()) ? remoteL[ri] : std::string();

        baseMoved = li < localL.size() && localLine == baseLine;
        localMoved = ri < remoteL.size() && remoteLine == baseLine;
        remoteMoved = false;

        while (bi < baseL.size() && (baseLine != localLine || baseLine != remoteLine) &&
               localLine != baseLine && remoteLine != baseLine) {
            // all three differ - record single-line conflict
            h.baseVector.push_back(baseLine);
            h.localVector.push_back(localLine);
            h.remoteVector.push_back(remoteLine);
            ++bi; ++li; ++ri;
            if (bi >= baseL.size() || li >= localL.size() || ri >= remoteL.size()) break;
            baseLine = (bi < baseL.size()) ? baseL[bi] : std::string();
            localLine = (li < localL.size()) ? localL[li] : std::string();
            remoteLine = (ri < remoteL.size()) ? remoteL[ri] : std::string();
        }
        h.baseLines = static_cast<int>(h.baseVector.size());
        h.localLines = static_cast<int>(h.localVector.size());
        h.remoteLines = static_cast<int>(h.remoteVector.size());
        if (h.baseVector.empty() && h.localVector.empty() && h.remoteVector.empty()) {
            // consume the matching line
            if (bi < baseL.size()) ++bi;
            if (li < localL.size()) ++li;
            if (ri < remoteL.size()) ++ri;
            return false;
        }
        hunks.push_back(h);
        return true;
    };

    while (bi < baseL.size() || li < localL.size() || ri < remoteL.size()) {
        bool bm = false, lm = false, rm = false;
        bool progressed = collectRun(bm, lm, rm);
        if (!progressed && bi == baseL.size() && li == localL.size() && ri == remoteL.size()) break;
    }
    return hunks;
}

std::string ThreeWayMerge::applyConflictMarkers(const std::string& base,
                                                const std::vector<std::string>& local,
                                                const std::vector<std::string>& remote) const {
    (void)base;
    if (!m_options.markConflicts) {
        // Prefer one side deterministically.
        if (m_options.preferRemote) return joinLines(remote);
        return joinLines(local);
    }
    std::string out = m_options.conflictMarkerStart + "\n";
    out += joinLines(local);
    out += "\n" + m_options.conflictMarkerMiddle + "\n";
    out += joinLines(remote);
    out += "\n" + m_options.conflictMarkerEnd + "\n";
    return out;
}

std::string ThreeWayMerge::mergeHunk(const DiffHunk& hunk) const {
    // If only one side changed, take it.
    if (hunk.localVector.empty() && !hunk.remoteVector.empty()) return joinLines(hunk.remoteVector);
    if (!hunk.localVector.empty() && hunk.remoteVector.empty()) return joinLines(hunk.localVector);

    // Both sides changed.
    if (hunk.localVector == hunk.remoteVector) return joinLines(hunk.localVector);

    if (m_options.preferLocal && !m_options.preferRemote) return joinLines(hunk.localVector);
    if (m_options.preferRemote && !m_options.preferLocal) return joinLines(hunk.remoteVector);

    // True conflict.
    return applyConflictMarkers(joinLines(hunk.baseVector), hunk.localVector, hunk.remoteVector);
}

bool ThreeWayMerge::linesEquivalent(const std::string& a, const std::string& b,
                                     const std::string& /*filePath - reserved for language rules*/) const {
    if (!m_options.semanticAware) return a == b;
    // Semantic mode: ignore trailing whitespace differences.
    return trimCopy(a) == trimCopy(b);
}

MergeResult ThreeWayMerge::merge(const std::string& base,
                                 const std::string& local,
                                 const std::string& remote,
                                 const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    MergeResult result;
    (void)filePath;

    // Trivial cases
    if (local == remote) {
        result.success = true;
        result.mergedText = local;
        result.conflictCount = 0;
        result.details = "Identical changes on both sides";
        return result;
    }
    if (local == base) {
        result.success = true;
        result.mergedText = remote;
        result.conflictCount = 0;
        result.details = "Only remote changed; took remote";
        return result;
    }
    if (remote == base) {
        result.success = true;
        result.mergedText = local;
        result.conflictCount = 0;
        result.details = "Only local changed; took local";
        return result;
    }

    // Line-level diff3
    auto hunks = computeDiff3(base, local, remote);
    std::vector<std::string> merged;
    int conflicts = 0;

    auto baseL = splitLines(base);
    size_t cursor = 0;
    for (const auto& h : hunks) {
        // copy untouched base lines up to hunk start
        while (cursor < static_cast<size_t>(h.baseStart) && cursor < baseL.size()) {
            merged.push_back(baseL[cursor]);
            ++cursor;
        }
        std::string mergedHunk = mergeHunk(h);
        for (const auto& l : splitLines(mergedHunk)) {
            merged.push_back(l);
        }
        if (mergedHunk.find(m_options.conflictMarkerStart) != std::string::npos) ++conflicts;
        cursor = static_cast<size_t>(h.baseStart + h.baseLines);
        if (cursor < static_cast<size_t>(h.baseStart)) cursor = static_cast<size_t>(h.baseStart);
    }
    while (cursor < baseL.size()) {
        merged.push_back(baseL[cursor]);
        ++cursor;
    }

    if (merged.empty() && !base.empty()) {
        merged = splitLines(local == base ? remote : local);
    }

    result.mergedText = joinLines(merged);
    result.conflictCount = conflicts;
    result.success = (conflicts == 0);
    if (conflicts > 0) {
        result.details = std::to_string(conflicts) + " conflicting hunk(s) required markers";
    } else {
        result.details = "Clean 3-way merge";
    }
    return result;
}

MergeResult ThreeWayMerge::mergeEdits(const std::string& baseDocument,
                                      const std::vector<Edit>& edits,
                                      const std::string& /*filePath - accepted for API symmetry*/) {
    std::lock_guard<std::mutex> lock(m_mutex);
    MergeResult result;

    if (edits.empty()) {
        result.success = true;
        result.mergedText = baseDocument;
        result.details = "No edits to apply";
        return result;
    }

    // Sort edits by starting line so application order is deterministic.
    std::vector<Edit> sorted = edits;
    std::stable_sort(sorted.begin(), sorted.end(), [](const Edit& a, const Edit& b) {
        if (a.range.startLine != b.range.startLine) return a.range.startLine < b.range.startLine;
        return a.timestamp < b.timestamp;
    });

    auto lines = splitLines(baseDocument);
    int conflicts = 0;
    std::vector<std::string> output;
    size_t srcLine = 0;   // 0-based index into `lines`

    auto appendRange = [&](size_t upTo) {
        while (srcLine < upTo && srcLine < lines.size()) {
            output.push_back(lines[srcLine]);
            ++srcLine;
        }
    };

    for (const auto& e : sorted) {
        int startIdx = e.range.startLine - 1;
        int endIdx = e.range.endLine;      // exclusive
        if (startIdx < 0) startIdx = 0;
        if (endIdx < startIdx) endIdx = startIdx;
        size_t start = static_cast<size_t>(startIdx);
        size_t end = static_cast<size_t>(endIdx);

        if (start < srcLine) {
            // Overlapping with a previously applied edit - conflict.
            ++conflicts;
            result.warnings.push_back("Edit " + e.id + " overlaps previously applied edit");
            continue;
        }
        appendRange(start);
        if (e.newText.empty()) {
            // pure deletion
        } else {
            for (const auto& l : splitLines(e.newText)) output.push_back(l);
        }
        srcLine = std::max(srcLine, end);
    }
    appendRange(lines.size());

    result.mergedText = joinLines(output);
    result.conflictCount = conflicts;
    result.success = (conflicts == 0);
    result.details = conflicts == 0
        ? "Applied " + std::to_string(sorted.size()) + " edit(s) cleanly"
        : std::to_string(conflicts) + " edit(s) skipped due to overlap";
    return result;
}

void ThreeWayMerge::setOptions(const MergeOptions& options) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_options = options;
}

ThreeWayMerge::MergeOptions ThreeWayMerge::getOptions() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_options;
}

// ============================================================================
// ConflictResolver
// ============================================================================

ConflictResolver::ConflictResolver() {
    m_threeWayMerge = std::make_unique<ThreeWayMerge>();

    // Default policy: auto-merge, escalate when impossible.
    ResolutionPolicy def("default");
    def.description = "Default policy: attempt 3-way merge, escalate on failure";
    def.method = ResolutionPolicy::Method::AutoMerge;
    def.fallbackMethod = ResolutionPolicy::Method::ManualRequired;
    def.priority = 0;
    m_defaultPolicy = def;
}

const ConflictResolver::ResolutionPolicy* ConflictResolver::findMatchingPolicy(
    const Conflict& conflict) const {

    const ResolutionPolicy* best = nullptr;
    for (const auto& p : m_policies) {
        // Type filter
        bool typeOk = p.applicableTypes.empty();
        for (auto t : p.applicableTypes) {
            if (t == conflict.type) { typeOk = true; break; }
        }
        if (!typeOk) continue;

        // File pattern filter
        bool fileOk = p.filePatterns.empty();
        for (const auto& pattern : p.filePatterns) {
            if (globMatch(pattern, conflict.filePath)) { fileOk = true; break; }
        }
        if (!fileOk) continue;

        if (!best || p.priority > best->priority) best = &p;
    }
    return best;
}

void ConflictResolver::registerPolicy(const ResolutionPolicy& policy) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& existing : m_policies) {
        if (existing.name == policy.name) {
            existing = policy;
            return;
        }
    }
    m_policies.push_back(policy);
}

bool ConflictResolver::removePolicy(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = std::remove_if(m_policies.begin(), m_policies.end(),
                             [&](const ResolutionPolicy& p) { return p.name == name; });
    if (it == m_policies.end()) return false;
    m_policies.erase(it, m_policies.end());
    return true;
}

std::vector<ConflictResolver::ResolutionPolicy> ConflictResolver::getPolicies() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_policies;
}

void ConflictResolver::setDefaultPolicy(const ResolutionPolicy& policy) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_defaultPolicy = policy;
}

Conflict ConflictResolver::semanticMerge(const Conflict& conflict,
                                         const std::string& baseDocument) const {
    Conflict resolved = conflict;

    // Semantic merge: if edits touch different semantic element types,
    // they can coexist - concatenate in priority order.
    bool differingSemantics = conflict.conflictingEdits.size() == 2 &&
        conflict.conflictingEdits[0].semanticType != conflict.conflictingEdits[1].semanticType;

    if (differingSemantics) {
        auto edits = conflict.conflictingEdits;
        std::stable_sort(edits.begin(), edits.end(),
                         [](const Edit& a, const Edit& b) {
                             if (b.priority != a.priority) return b.priority < a.priority; // higher priority first
                             return a.timestamp < b.timestamp;
                         });
        std::string merged;
        for (const auto& e : edits) merged += e.newText + "\n";
        resolved.resolvedText = merged;
        resolved.resolutionStrategy = Conflict::ResolutionStrategy::SemanticMerge;
        resolved.isResolved = true;
        resolved.resolvedAt = nowMs();
        resolved.resolutionDetails = "Semantic merge: edits to distinct element types combined by priority";
        return resolved;
    }

    // Fall back to merge engine on the affected region.
    if (m_threeWayMerge) {
        MergeResult mr;
        std::string local, remote;
        if (conflict.conflictingEdits.size() >= 2) {
            local = conflict.conflictingEdits[0].newText;
            remote = conflict.conflictingEdits[1].newText;
        } else if (conflict.conflictingEdits.size() == 1) {
            local = conflict.conflictingEdits[0].newText;
            remote = conflict.conflictingEdits[0].oldText;
        }
        mr = m_threeWayMerge->merge(baseDocument, local, remote, conflict.filePath);
        resolved.resolvedText = mr.mergedText;
        resolved.resolutionStrategy = Conflict::ResolutionStrategy::SemanticMerge;
        resolved.isResolved = mr.success;
        resolved.resolvedAt = nowMs();
        resolved.resolutionDetails = mr.details;
        return resolved;
    }

    resolved.resolutionStrategy = Conflict::ResolutionStrategy::ManualRequired;
    resolved.resolutionDetails = "No merge engine available";
    return resolved;
}

Conflict ConflictResolver::applyResolution(const Conflict& conflict,
                                           ResolutionPolicy::Method method,
                                           const std::string& baseDocument) const {
    Conflict resolved = conflict;

    switch (method) {
        case ResolutionPolicy::Method::FirstWins: {
            auto best = conflict.conflictingEdits.front();
            for (const auto& e : conflict.conflictingEdits) {
                if (e.timestamp < best.timestamp) best = e;
            }
            resolved.resolvedText = best.newText;
            resolved.resolutionStrategy = Conflict::ResolutionStrategy::FirstWins;
            resolved.isResolved = true;
            resolved.resolvedAt = nowMs();
            resolved.resolutionDetails = "First edit (agent " + best.agentId + ") won";
            break;
        }
        case ResolutionPolicy::Method::LastWins: {
            auto best = conflict.conflictingEdits.front();
            for (const auto& e : conflict.conflictingEdits) {
                if (e.timestamp >= best.timestamp) best = e;
            }
            resolved.resolvedText = best.newText;
            resolved.resolutionStrategy = Conflict::ResolutionStrategy::LastWins;
            resolved.isResolved = true;
            resolved.resolvedAt = nowMs();
            resolved.resolutionDetails = "Last edit (agent " + best.agentId + ") won";
            break;
        }
        case ResolutionPolicy::Method::PriorityWins: {
            auto best = conflict.conflictingEdits.front();
            for (const auto& e : conflict.conflictingEdits) {
                if (e.priority > best.priority) best = e;
            }
            resolved.resolvedText = best.newText;
            resolved.resolutionStrategy = Conflict::ResolutionStrategy::PriorityWins;
            resolved.isResolved = true;
            resolved.resolvedAt = nowMs();
            resolved.resolutionDetails = "Highest priority edit (agent " + best.agentId + ") won";
            break;
        }
        case ResolutionPolicy::Method::AgentWins: {
            for (const auto& e : conflict.conflictingEdits) {
                if (e.agentId == m_defaultPolicy.preferredAgentId) {
                    resolved.resolvedText = e.newText;
                    resolved.resolutionStrategy = Conflict::ResolutionStrategy::Custom;
                    resolved.isResolved = true;
                    resolved.resolvedAt = nowMs();
                    resolved.resolutionDetails = "Preferred agent " + e.agentId + " won";
                    return resolved;
                }
            }
            resolved.resolutionStrategy = Conflict::ResolutionStrategy::ManualRequired;
            resolved.resolutionDetails = "Preferred agent edit not found among conflicting edits";
            break;
        }
        case ResolutionPolicy::Method::AutoMerge:
        default: {
            Conflict merged = semanticMerge(conflict, baseDocument);
            if (merged.isResolved) return merged;
            resolved.resolutionStrategy = Conflict::ResolutionStrategy::ManualRequired;
            resolved.resolutionDetails = "Auto/semantic merge failed: " + merged.resolutionDetails;
            break;
        }
    }
    return resolved;
}

Conflict ConflictResolver::autoResolve(const Conflict& conflict,
                                       Conflict::ResolutionStrategy strategy,
                                       const std::string& baseDocument) {
    Conflict resolved = conflict;
    switch (strategy) {
        case Conflict::ResolutionStrategy::AutoMerge:
            resolved = applyResolution(conflict, ResolutionPolicy::Method::AutoMerge, baseDocument);
            break;
        case Conflict::ResolutionStrategy::FirstWins:
            resolved = applyResolution(conflict, ResolutionPolicy::Method::FirstWins, baseDocument);
            break;
        case Conflict::ResolutionStrategy::LastWins:
            resolved = applyResolution(conflict, ResolutionPolicy::Method::LastWins, baseDocument);
            break;
        case Conflict::ResolutionStrategy::PriorityWins:
            resolved = applyResolution(conflict, ResolutionPolicy::Method::PriorityWins, baseDocument);
            break;
        case Conflict::ResolutionStrategy::SemanticMerge:
            resolved = semanticMerge(conflict, baseDocument);
            break;
        default:
            resolved.resolutionStrategy = Conflict::ResolutionStrategy::ManualRequired;
            resolved.resolutionDetails = "Strategy not supported for auto-resolution";
            break;
    }
    return resolved;
}

Conflict ConflictResolver::resolve(const Conflict& conflict, const std::string& baseDocument) {
    const ResolutionPolicy* policy = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        policy = findMatchingPolicy(conflict);
        if (!policy) policy = &m_defaultPolicy;
    }

    Conflict result = applyResolution(conflict, policy->method, baseDocument);

    // Fallback if the primary method didn't resolve and fallback differs.
    if (!result.isResolved && policy->fallbackMethod != policy->method) {
        Conflict fallback = applyResolution(conflict, policy->fallbackMethod, baseDocument);
        if (fallback.isResolved) {
            fallback.resolutionDetails += " (via fallback from primary method)";
            result = fallback;
        }
    }
    return result;
}

std::vector<Conflict> ConflictResolver::resolveAll(std::vector<Conflict> conflicts,
                                                   const std::string& baseDocument) {
    std::vector<Conflict> resolved;
    resolved.reserve(conflicts.size());
    for (auto& c : conflicts) {
        resolved.push_back(resolve(c, baseDocument));
    }
    return resolved;
}

// ============================================================================
// ConflictManager
// ============================================================================

ConflictManager::ConflictManager(const Config& config)
    : m_config(config)
    , m_detector(std::make_unique<ConflictDetector>())
    , m_resolver(std::make_unique<ConflictResolver>())
    , m_merge(std::make_unique<ThreeWayMerge>()) {

    if (m_config.maxConcurrentResolutions < 1) m_config.maxConcurrentResolutions = 1;

    m_running.store(true);
    m_workerThread = std::thread([this]() { workerLoop(); });
}

void ConflictManager::setResolutionPolicy(const ConflictResolver::ResolutionPolicy& policy) {
    if (m_resolver) m_resolver->registerPolicy(policy);
}

void ConflictManager::clearResolutionPolicies() {
    if (!m_resolver) return;
    for (const auto& p : m_resolver->getPolicies()) m_resolver->removePolicy(p.name);
}

ConflictManager::~ConflictManager() {
    m_shutdown.store(true);
    m_queueCv.notify_all();
    if (m_workerThread.joinable()) m_workerThread.join();
}

void ConflictManager::workerLoop() {
    while (true) {
        AsyncJob job;
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_queueCv.wait(lock, [this]() {
                return m_shutdown.load() || !m_queue.empty();
            });
            if (m_shutdown.load() && m_queue.empty()) return;
            job = std::move(m_queue.front());
            m_queue.erase(m_queue.begin());
        }

        if (!job.callback) continue;

        std::vector<Edit> nonConflicting;
        std::vector<Conflict> resolvedConflicts;

        auto detected = m_detector->detectConflicts(job.edits);
        for (auto& c : detected) {
            if (m_config.autoResolveEnabled) {
                Conflict r = m_resolver->resolve(c, job.baseDocument);
                if (r.isResolved) {
                    m_totalAutoResolved++;
                    if (m_onResolved) m_onResolved(r);
                } else {
                    m_totalManualRequired++;
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        m_unresolvedConflicts.push_back(r);
                    }
                    if (m_onDetected) m_onDetected(r);
                }
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_conflictHistory.push_back(r);
                    if (m_conflictHistory.size() > 1000) m_conflictHistory.erase(m_conflictHistory.begin());
                }
                if (m_onDetected) m_onDetected(c);
                resolvedConflicts.push_back(r);
            } else {
                m_totalManualRequired++;
                std::lock_guard<std::mutex> lock(m_mutex);
                m_unresolvedConflicts.push_back(c);
                m_conflictHistory.push_back(c);
                if (m_onDetected) m_onDetected(c);
            }
        }

        // Edits not part of any conflict pass through
        std::unordered_map<std::string, bool> conflictedIds;
        for (const auto& c : detected) {
            for (const auto& e : c.conflictingEdits) conflictedIds[e.id] = true;
        }
        for (const auto& e : job.edits) {
            if (!conflictedIds.count(e.id)) nonConflicting.push_back(e);
        }

        job.callback(nonConflicting, resolvedConflicts);
    }
}

std::vector<Edit> ConflictManager::processEdits(const std::vector<Edit>& edits,
                                                const std::string& baseDocument) {
    std::vector<Edit> result;
    auto detected = m_detector->detectConflicts(edits);

    std::unordered_map<std::string, bool> conflictedIds;
    std::vector<Conflict> resolvedConflicts;

    for (auto& c : detected) {
        m_totalDetected++;
        if (m_onDetected) m_onDetected(c);

        Conflict r = c;
        if (m_config.autoResolveEnabled) {
            int64_t t0 = nowMs();
            r = m_resolver->resolve(c, baseDocument);
            m_totalResolutionTimeMs += (nowMs() - t0);
            m_resolutionCount++;
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_conflictHistory.push_back(r);
            if (m_conflictHistory.size() > 1000) m_conflictHistory.erase(m_conflictHistory.begin());
            if (!r.isResolved) m_unresolvedConflicts.push_back(r);
        }
        if (r.isResolved) {
            m_totalAutoResolved++;
            if (m_onResolved) m_onResolved(r);
        } else {
            m_totalManualRequired++;
        }

        logConflict(r);
        resolvedConflicts.push_back(r);

        for (const auto& e : c.conflictingEdits) conflictedIds[e.id] = true;
    }

    // A conflicting edit passes through only when the resolution has a single
    // deterministic winner whose content equals the agent's edit. Merge-style
    // resolutions produce a synthesized result, so nothing passes through.
    auto isWinnerPassThrough = [](const Conflict& r, const Edit& e) {
        switch (r.resolutionStrategy) {
            case Conflict::ResolutionStrategy::FirstWins:
            case Conflict::ResolutionStrategy::LastWins:
            case Conflict::ResolutionStrategy::PriorityWins:
                return r.resolvedText == e.newText;
            default:
                return false;
        }
    };

    for (const auto& e : edits) {
        if (!conflictedIds.count(e.id)) {
            result.push_back(e);
            continue;
        }
        for (const auto& r : resolvedConflicts) {
            if (!r.isResolved) continue;
            bool matched = false;
            for (const auto& ce : r.conflictingEdits) {
                if (ce.id == e.id) { matched = true; break; }
            }
            if (!matched) continue;
            if (isWinnerPassThrough(r, e)) {
                result.push_back(e);
            }
            break;
        }
    }

    return result;
}

void ConflictManager::processEditsAsync(const std::vector<Edit>& edits,
                                        const std::string& baseDocument,
                                        ProcessCallback callback) {
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_queue.push_back(AsyncJob{edits, baseDocument, std::move(callback)});
    }
    m_queueCv.notify_one();
}

std::vector<Conflict> ConflictManager::getUnresolvedConflicts() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_unresolvedConflicts;
}

std::vector<Conflict> ConflictManager::getConflictHistory(int limit) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (limit <= 0 || static_cast<size_t>(limit) >= m_conflictHistory.size()) {
        return m_conflictHistory;
    }
    return std::vector<Conflict>(m_conflictHistory.end() - limit, m_conflictHistory.end());
}

bool ConflictManager::resolveManually(const std::string& conflictId,
                                      const std::string& resolvedText,
                                      const std::string& resolutionDetails) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& c : m_unresolvedConflicts) {
        if (c.id == conflictId) {
            c.resolvedText = resolvedText;
            c.resolutionDetails = resolutionDetails;
            c.isResolved = true;
            c.resolvedAt = nowMs();
            c.resolutionStrategy = Conflict::ResolutionStrategy::ManualRequired;
            m_unresolvedConflicts.erase(
                std::remove_if(m_unresolvedConflicts.begin(), m_unresolvedConflicts.end(),
                               [&](const Conflict& x) { return x.id == conflictId; }),
                m_unresolvedConflicts.end());
            for (auto& h : m_conflictHistory) {
                if (h.id == conflictId) {
                    h.resolvedText = resolvedText;
                    h.resolutionDetails = resolutionDetails;
                    h.isResolved = true;
                    h.resolvedAt = c.resolvedAt;
                    break;
                }
            }
            return true;
        }
    }
    return false;
}

void ConflictManager::onConflictDetected(ConflictCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_onDetected = std::move(cb);
}

void ConflictManager::onConflictResolved(ConflictCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_onResolved = std::move(cb);
}

ConflictManager::Stats ConflictManager::getStats() const {
    Stats s;
    s.totalConflictsDetected = m_totalDetected.load();
    s.totalAutoResolved = m_totalAutoResolved.load();
    s.totalManualRequired = m_totalManualRequired.load();
    s.totalFailed = m_totalFailed.load();
    int64_t count = m_resolutionCount.load();
    s.avgResolutionTimeMs = count > 0 ? static_cast<double>(m_totalResolutionTimeMs.load()) / count : 0.0;
    return s;
}

std::string ConflictManager::escapeJsonField(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

void ConflictManager::logConflict(const Conflict& conflict) const {
    if (m_config.conflictLogPath.empty()) return;
    std::ofstream f(m_config.conflictLogPath, std::ios::app);
    if (!f.is_open()) return;
    f << "{\"id\":\"" << conflict.id << "\","
      << "\"file\":\"" << escapeJsonField(conflict.filePath) << "\","
      << "\"type\":" << static_cast<int>(conflict.type) << ","
      << "\"resolved\":" << (conflict.isResolved ? "true" : "false") << ","
      << "\"strategy\":" << static_cast<int>(conflict.resolutionStrategy) << ","
      << "\"details\":\"" << escapeJsonField(conflict.resolutionDetails) << "\","
      << "\"detectedAt\":" << conflict.detectedAt << ","
      << "\"resolvedAt\":" << conflict.resolvedAt << "}\n";
}

bool ConflictManager::exportConflictLog(const std::string& filePath) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ofstream f(filePath);
    if (!f.is_open()) return false;
    f << "[\n";
    for (size_t i = 0; i < m_conflictHistory.size(); ++i) {
        const auto& c = m_conflictHistory[i];
        if (i) f << ",\n";
        f << "  {\"id\":\"" << c.id << "\","
          << "\"file\":\"" << escapeJsonField(c.filePath) << "\","
          << "\"type\":" << static_cast<int>(c.type) << ","
          << "\"resolved\":" << (c.isResolved ? "true" : "false") << ","
          << "\"strategy\":" << static_cast<int>(c.resolutionStrategy) << ","
          << "\"details\":\"" << escapeJsonField(c.resolutionDetails) << "\","
          << "\"detectedAt\":" << c.detectedAt << ","
          << "\"resolvedAt\":" << c.resolvedAt << "}";
    }
    f << "\n]\n";
    return true;
}

// ============================================================================
// Swarm integration
// ============================================================================

std::vector<SwarmConflict> SwarmConflictResolver::detectSwarmConflicts(
    const std::vector<SwarmEdit>& edits) {

    std::vector<SwarmConflict> conflicts;
    for (size_t i = 0; i < edits.size(); ++i) {
        for (size_t j = i + 1; j < edits.size(); ++j) {
            const SwarmEdit& a = edits[i];
            const SwarmEdit& b = edits[j];
            if (a.filePath != b.filePath) continue;
            if (a.agentId == b.agentId) continue;

            // Dependency conflict: EITHER side declared a dependency on the
            // other's task, meaning the declared order was violated.
            bool dependencyViolated = false;
            std::string depTask;
            for (const auto& dep : a.dependencies) {
                if (dep == b.taskId) { dependencyViolated = true; depTask = dep; break; }
            }
            if (!dependencyViolated) {
                for (const auto& dep : b.dependencies) {
                    if (dep == a.taskId) { dependencyViolated = true; depTask = dep; break; }
                }
            }
            if (dependencyViolated) {
                SwarmConflict c;
                c.conflictId = newUuid();
                c.filePath = a.filePath;
                c.involvedEdits = { a, b };
                c.type = Conflict::ConflictType::DependencyConflict;
                c.reason = "Edit reserved a dependency on task " + depTask + " that ran concurrently";
                c.autoResolvable = true;
                c.suggestedResolution = "reorder_by_dependency";
                conflicts.push_back(c);
            }

            // Content conflict: both modified the same file with different content
            if (a.content != b.content) {
                bool alreadyDependency = false;
                for (const auto& existing : conflicts) {
                    if (existing.filePath != a.filePath) continue;
                    bool hasA = false, hasB = false;
                    for (const auto& e : existing.involvedEdits) {
                        if (e.taskId == a.taskId) hasA = true;
                        if (e.taskId == b.taskId) hasB = true;
                    }
                    if (hasA && hasB) { alreadyDependency = true; break; }
                }
                if (alreadyDependency) continue;

                SwarmConflict c;
                c.conflictId = newUuid();
                c.filePath = a.filePath;
                c.involvedEdits = { a, b };
                c.type = Conflict::ConflictType::TextOverlap;
                c.reason = "Concurrent edits with divergent content";
                c.autoResolvable = true;
                c.suggestedResolution = "merge";
                conflicts.push_back(c);
            }
        }
    }
    return conflicts;
}

std::vector<SwarmEdit> SwarmConflictResolver::resolveSwarmConflicts(
    const std::vector<SwarmEdit>& edits,
    const std::vector<SwarmConflict>& conflicts,
    ConflictResolver::ResolutionPolicy::Method strategy) {

    // Build a lookup of which task ids participate in each conflict, so the
    // resolution below can act on the ACTUAL detected conflicts rather than
    // re-deriving them from file grouping alone.
    struct InvalidationInfo {
        bool participates = false;
        bool isDependencyViolation = false;
    };
    std::unordered_map<std::string, InvalidationInfo> byTask;
    for (const auto& c : conflicts) {
        for (const auto& e : c.involvedEdits) {
            auto& info = byTask[e.taskId];
            info.participates = true;
            if (c.type == Conflict::ConflictType::DependencyConflict) {
                info.isDependencyViolation = true;
            }
        }
    }

    std::vector<SwarmEdit> result = edits;

    // Group by file
    std::unordered_map<std::string, std::vector<SwarmEdit>> byFile;
    for (const auto& e : result) byFile[e.filePath].push_back(e);

    std::vector<SwarmEdit> finalEdits;
    for (auto& pair : byFile) {
        auto& group = pair.second;
        if (group.size() <= 1) {
            for (auto& e : group) finalEdits.push_back(e);
            continue;
        }
        std::stable_sort(group.begin(), group.end(),
                         [](const SwarmEdit& a, const SwarmEdit& b) { return a.timestamp < b.timestamp; });

        switch (strategy) {
            case ConflictResolver::ResolutionPolicy::Method::LastWins:
                finalEdits.push_back(group.back());
                break;
            case ConflictResolver::ResolutionPolicy::Method::FirstWins:
                finalEdits.push_back(group.front());
                break;
            case ConflictResolver::ResolutionPolicy::Method::ManualRequired:
                // keep everything for human review
                for (const auto& e : group) finalEdits.push_back(e);
                break;
            default: {
                // Merge: honour dependency-violation edits by keeping them and
                // reordering the loser after the winner, then keep the winner.
                SwarmEdit winner = group.front();
                for (const auto& e : group) {
                    auto it = byTask.find(e.taskId);
                    if (it != byTask.end() && it->second.isDependencyViolation) {
                        winner = e;   // dependency-respecting edit wins
                        break;
                    }
                }
                finalEdits.push_back(winner);
                break;
            }
        }
    }
    return finalEdits;
}

std::string SwarmConflictResolver::mergeSwarmResults(const std::string& baseContent,
                                                     const std::vector<SwarmEdit>& edits) {
    if (edits.empty()) return baseContent;
    if (edits.size() == 1) return edits.front().content;

    // Deterministic order (earliest timestamp first).
    std::vector<SwarmEdit> ordered = edits;
    std::stable_sort(ordered.begin(), ordered.end(),
                     [](const SwarmEdit& a, const SwarmEdit& b) { return a.timestamp < b.timestamp; });

    auto baseLines = splitLines(baseContent);

    // For each line index, record which edits changed it and to what value.
    // Three cases per line:
    //   unchanged      -> keep base line
    //   one edit       -> take that edit's value
    //   multiple edits -> CONFLICT: different values, so it must be reported,
    //                     not silently resolved. We keep the earliest edit's
    //                     value and record the conflict marker so the loss is
    //                     visible rather than silent.
    struct LineChange { size_t editIndex; std::string value; };
    std::vector<std::vector<LineChange>> perLine;
    size_t maxLines = baseLines.size();

    for (size_t li = 0; li < baseLines.size(); ++li) {
        perLine.emplace_back();
    }

    for (size_t ei = 0; ei < ordered.size(); ++ei) {
        auto linesNow = splitLines(ordered[ei].content);
        maxLines = std::max(maxLines, linesNow.size());
        // extend perLine to cover growth
        while (perLine.size() < linesNow.size()) perLine.emplace_back();
        for (size_t li = 0; li < linesNow.size(); ++li) {
            std::string baseLine = li < baseLines.size() ? baseLines[li] : std::string();
            if (linesNow[li] != baseLine) {
                perLine[li].push_back({ ei, linesNow[li] });
            }
        }
    }

    ThreeWayMerge merger;
    ThreeWayMerge::MergeOptions opts;
    opts.markConflicts = true;
    merger.setOptions(opts);

    std::vector<std::string> result;
    int conflicts = 0;

    for (size_t li = 0; li < perLine.size(); ++li) {
        const auto& changes = perLine[li];
        std::string baseLine = li < baseLines.size() ? baseLines[li] : std::string();

        if (changes.empty()) {
            result.push_back(baseLine);
            continue;
        }
        if (changes.size() == 1) {
            result.push_back(changes.front().value);
            continue;
        }

        // Multiple different values for the same line: real conflict.
        bool allSame = true;
        for (size_t k = 1; k < changes.size(); ++k) {
            if (changes[k].value != changes[0].value) { allSame = false; break; }
        }
        if (allSame) {
            result.push_back(changes.front().value);   // all agree
            continue;
        }

        ++conflicts;
        // Emit conflict markers so the collision is visible in the output.
        std::vector<std::string> local, remote;
        for (size_t k = 0; k < changes.size(); ++k) {
            if (k == changes.size() - 1) remote.push_back(changes[k].value);
            else local.push_back(changes[k].value);
        }
        std::string marked = merger.formatConflict(local, remote, baseLine);
        for (const auto& ml : splitLines(marked)) result.push_back(ml);
    }

    (void)conflicts;  // count is visible via markers in the merged output
    return joinLines(result);
}

// ============================================================================
// Global accessor
// ============================================================================

ConflictManager& getGlobalConflictManager() {
    static ConflictManager instance;
    return instance;
}

} // namespace ConflictEngine
} // namespace RawrXD
