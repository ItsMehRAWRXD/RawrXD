#pragma once

#include "deep2/AgentToolRegistry.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace RawrXD::Agentic {

enum class MergeStatus : std::uint8_t {
    Applied,
    Conflict,
    StaleBase,
    ToolFailure,
    InvalidProposal
};

struct LineEdit final {
    std::uint64_t agentId{};
    std::size_t startLine{}; // 1-based inclusive
    std::size_t endLine{};   // 1-based inclusive; endLine < startLine = insertion before startLine
    std::string replacement{};
};

struct MergeProposal final {
    std::filesystem::path file{};
    std::uint64_t baseHash{};
    std::vector<LineEdit> edits{};
};

struct MergeOutcome final {
    MergeStatus status{MergeStatus::InvalidProposal};
    std::string mergedText{};
    std::string detail{};
    std::size_t conflictCount{};
};

struct MergeAuthorityReceipt final {
    std::uint64_t authorityReads{};
    std::uint64_t authorityWrites{};
    std::uint64_t proposals{};
    std::uint64_t conflictsDetected{};
    std::uint64_t staleBasesRejected{};
    std::uint64_t directBypassAttempts{};
    std::uint64_t failures{};

    [[nodiscard]] bool pass() const noexcept;
    [[nodiscard]] std::string text() const;
};

class MultiAgentMergeAuthority final {
public:
    explicit MultiAgentMergeAuthority(AgentToolRegistry& registry);

    MergeOutcome mergeAndApply(
        const MergeProposal& proposal,
        const std::filesystem::path& workspace,
        std::string readTool = "read-file",
        std::string writeTool = "write-file");

    static std::uint64_t contentHash(std::string_view text) noexcept;
    static MergeOutcome mergeText(std::string_view current, const MergeProposal& proposal);

    void noteDirectBypassAttempt() noexcept;
    [[nodiscard]] const MergeAuthorityReceipt& receipt() const noexcept { return receipt_; }

private:
    AgentToolRegistry& registry_;
    MergeAuthorityReceipt receipt_{};
};

[[nodiscard]] const char* toString(MergeStatus status) noexcept;

} // namespace RawrXD::Agentic
