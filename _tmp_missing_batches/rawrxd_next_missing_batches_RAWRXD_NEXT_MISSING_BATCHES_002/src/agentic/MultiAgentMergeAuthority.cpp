#include "MultiAgentMergeAuthority.hpp"

#include <algorithm>
#include <sstream>
#include <string_view>

namespace RawrXD::Agentic {
namespace {

std::vector<std::string> splitLines(std::string_view text) {
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start <= text.size()) {
        const auto nl = text.find('\n', start);
        const auto end = nl == std::string_view::npos ? text.size() : nl;
        std::string line(text.substr(start, end - start));
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(std::move(line));
        if (nl == std::string_view::npos) break;
        start = nl + 1;
    }
    if (!lines.empty() && lines.back().empty() && !text.empty() && text.back() == '\n') {
        lines.pop_back();
    }
    return lines;
}

std::string joinLines(const std::vector<std::string>& lines) {
    std::string out;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        out += lines[i];
        if (i + 1 < lines.size()) out.push_back('\n');
    }
    return out;
}

std::vector<std::string> replacementLines(std::string_view text) {
    if (text.empty()) return {};
    return splitLines(text);
}

bool overlaps(const LineEdit& a, const LineEdit& b) noexcept {
    // Insertions are treated as a point at startLine.
    const auto a0 = a.startLine;
    const auto a1 = a.endLine < a.startLine ? a.startLine : a.endLine;
    const auto b0 = b.startLine;
    const auto b1 = b.endLine < b.startLine ? b.startLine : b.endLine;
    return !(a1 < b0 || b1 < a0);
}

} // namespace

bool MergeAuthorityReceipt::pass() const noexcept {
    return proposals > 0 && authorityReads > 0 && directBypassAttempts == 0 && failures == 0;
}

std::string MergeAuthorityReceipt::text() const {
    std::ostringstream o;
    o << "=== RAWRXD_MULTI_AGENT_MERGE_AUTHORITY_001 ===\n";
    o << "PROPOSALS=" << proposals << "\n";
    o << "AUTHORITY_READS=" << authorityReads << "\n";
    o << "AUTHORITY_WRITES=" << authorityWrites << "\n";
    o << "CONFLICTS_DETECTED=" << conflictsDetected << "\n";
    o << "STALE_BASES_REJECTED=" << staleBasesRejected << "\n";
    o << "DIRECT_BYPASS_ATTEMPTS=" << directBypassAttempts << "\n";
    o << "FAILURES=" << failures << "\n";
    o << "VERDICT=" << (pass() ? "PASS" : "FAIL") << "\n";
    return o.str();
}

MultiAgentMergeAuthority::MultiAgentMergeAuthority(AgentToolRegistry& registry)
    : registry_(registry) {}

std::uint64_t MultiAgentMergeAuthority::contentHash(std::string_view text) noexcept {
    // Stable FNV-1a fingerprint used only for optimistic-concurrency staleness.
    // It is not a security hash and is intentionally dependency-free.
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : text) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

MergeOutcome MultiAgentMergeAuthority::mergeText(
    std::string_view current,
    const MergeProposal& proposal) {

    if (proposal.file.empty() || proposal.edits.empty()) {
        return {MergeStatus::InvalidProposal, {}, "empty file or edit set", 0};
    }
    if (proposal.baseHash != contentHash(current)) {
        return {MergeStatus::StaleBase, {}, "base content changed since proposal", 0};
    }

    for (std::size_t i = 0; i < proposal.edits.size(); ++i) {
        const auto& a = proposal.edits[i];
        if (a.startLine == 0 || a.agentId == 0) {
            return {MergeStatus::InvalidProposal, {}, "invalid edit coordinates/agent id", 0};
        }
        for (std::size_t j = i + 1; j < proposal.edits.size(); ++j) {
            const auto& b = proposal.edits[j];
            if (a.agentId != b.agentId && overlaps(a, b) && a.replacement != b.replacement) {
                return {MergeStatus::Conflict, {}, "overlapping edits from independent agents", 1};
            }
        }
    }

    auto lines = splitLines(current);
    auto edits = proposal.edits;
    std::sort(edits.begin(), edits.end(), [](const LineEdit& a, const LineEdit& b) {
        if (a.startLine != b.startLine) return a.startLine > b.startLine;
        return a.endLine > b.endLine;
    });

    for (const auto& e : edits) {
        if (e.startLine > lines.size() + 1) {
            return {MergeStatus::InvalidProposal, {}, "edit start exceeds file length", 0};
        }
        const std::size_t begin = e.startLine - 1;
        const bool insertion = e.endLine < e.startLine;
        std::size_t eraseEnd = begin;
        if (!insertion) {
            if (e.endLine == 0 || e.endLine > lines.size()) {
                return {MergeStatus::InvalidProposal, {}, "edit end exceeds file length", 0};
            }
            eraseEnd = e.endLine; // vector end iterator index is inclusive-line value
        }
        auto replacement = replacementLines(e.replacement);
        auto first = lines.begin() + static_cast<std::ptrdiff_t>(begin);
        auto last = lines.begin() + static_cast<std::ptrdiff_t>(eraseEnd);
        lines.erase(first, last);
        lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(begin), replacement.begin(), replacement.end());
    }

    return {MergeStatus::Applied, joinLines(lines), "deterministic non-overlapping merge", 0};
}

MergeOutcome MultiAgentMergeAuthority::mergeAndApply(
    const MergeProposal& proposal,
    const std::filesystem::path& workspace,
    std::string readTool,
    std::string writeTool) {

    ++receipt_.proposals;
    ToolRequest read;
    read.surface = AgentToolSurface::AgentCore;
    read.tool_id = std::move(readTool);
    read.args = {proposal.file.string()};
    read.working_directory = workspace;
    ToolContext context;

    ++receipt_.authorityReads;
    auto readResult = registry_.invoke(std::move(read), context);
    if (!readResult.ok()) {
        ++receipt_.failures;
        return {MergeStatus::ToolFailure, {}, readResult.stderr_text, 0};
    }

    auto merged = mergeText(readResult.stdout_text, proposal);
    if (merged.status == MergeStatus::Conflict) {
        receipt_.conflictsDetected += merged.conflictCount;
        return merged; // conflict is a handled outcome: no write occurs.
    }
    if (merged.status == MergeStatus::StaleBase) {
        ++receipt_.staleBasesRejected;
        return merged; // fail closed and force agents to re-read.
    }
    if (merged.status != MergeStatus::Applied) {
        ++receipt_.failures;
        return merged;
    }

    ToolRequest write;
    write.surface = AgentToolSurface::AgentCore;
    write.tool_id = std::move(writeTool);
    write.args = {proposal.file.string()};
    write.stdin_text = merged.mergedText;
    write.working_directory = workspace;

    ++receipt_.authorityWrites;
    auto writeResult = registry_.invoke(std::move(write), context);
    if (!writeResult.ok()) {
        ++receipt_.failures;
        return {MergeStatus::ToolFailure, {}, writeResult.stderr_text, 0};
    }
    return merged;
}

void MultiAgentMergeAuthority::noteDirectBypassAttempt() noexcept {
    ++receipt_.directBypassAttempts;
    ++receipt_.failures;
}

const char* toString(MergeStatus status) noexcept {
    switch (status) {
        case MergeStatus::Applied: return "Applied";
        case MergeStatus::Conflict: return "Conflict";
        case MergeStatus::StaleBase: return "StaleBase";
        case MergeStatus::ToolFailure: return "ToolFailure";
        case MergeStatus::InvalidProposal: return "InvalidProposal";
    }
    return "Unknown";
}

} // namespace RawrXD::Agentic
