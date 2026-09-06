// ============================================================================
// W0Types.hpp — HexMag W0 / Deep2-W0 weightless coding model (zero tensor weights)
// ============================================================================
// NO WEIGHTS · NO STOCHASTIC INFERENCE · NO REQUIRED GPU · NO UNVERIFIED FINAL
// ============================================================================
#ifndef RAWRXD_DEEP2W0_W0_TYPES_HPP
#define RAWRXD_DEEP2W0_W0_TYPES_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace W0 {

enum class NodeType : uint8_t {
    Unknown = 0,
    File,
    Function,
    Variable,
    Error,
    Intent,
    Rule,
    Patch,
    Test,
    Constraint,
    Fact,
};

enum class RelType : uint8_t {
    Declares = 1,
    DefinedIn,
    FailsWith,
    FixedBy,
    Requires,
    VerifiedBy,
    Contradicts,
};

enum class TransformOp : uint8_t {
    None = 0,
    ChangeLiteral,
    RenameSymbol,
    AddInclude,
    ReplaceFunctionBody,
    MakeFailClosed,
};

struct W0Node {
    uint64_t id = 0;
    NodeType type = NodeType::Unknown;
    std::string text;
    std::vector<uint64_t> relationships;
    std::vector<uint64_t> constraints;
    std::vector<uint64_t> provenance;
};

struct CandidateScore {
    bool compiles = false;
    uint32_t failedTests = 0;
    uint32_t violatedConstraints = 0;
    uint32_t unrelatedFilesChanged = 0;
    uint32_t editDistance = 0;

    /// Lexicographical constraint ranking (no learned weights).
    bool beats(const CandidateScore& o) const {
        if (compiles != o.compiles) return compiles && !o.compiles;
        if (failedTests != o.failedTests) return failedTests < o.failedTests;
        if (violatedConstraints != o.violatedConstraints)
            return violatedConstraints < o.violatedConstraints;
        if (unrelatedFilesChanged != o.unrelatedFilesChanged)
            return unrelatedFilesChanged < o.unrelatedFilesChanged;
        return editDistance < o.editDistance;
    }
};

struct W0Patch {
    TransformOp op = TransformOp::None;
    std::string path;
    std::string before;
    std::string after;
    std::string rationale;
};

struct W0Evidence {
    std::string kind;   // compile | test | structural | retrieval
    std::string payload;
    bool passes = false;
};

struct W0Request {
    std::string task;
    std::string workspaceRoot; // directory containing sources
    bool allowNetwork = false;
};

struct W0Result {
    bool needInput = false;
    bool success = false;
    std::string error;
    std::string intentSummary;
    std::vector<W0Patch> patches;
    std::string candidateSource; // unified patched file text (candidate only)
    CandidateScore score;
    std::vector<W0Evidence> evidence;
    std::string surface; // template-realized human response
    /// Debug ladder (first deviation is authority). Printed by certs.
    std::vector<std::string> ladder;
};

inline constexpr const char* kW0Contract =
    "NO_WEIGHTS=1\n"
    "NO_STOCHASTIC_INFERENCE=1\n"
    "NO_REQUIRED_GPU=1\n"
    "NO_UNVERIFIED_FINAL=1\n"
    "FLOAT_OPS=0\n"
    "TENSOR_WEIGHTS=0\n";

} // namespace W0
} // namespace RawrXD

#endif
