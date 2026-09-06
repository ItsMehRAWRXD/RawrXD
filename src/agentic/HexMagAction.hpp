#pragma once
// HexMag / Agent internal actions — not TOOL_CALL serialization.
// Presentation syntax (TOOL_CALL, JSON, …) is irrelevant internally.

#include <cstdint>
#include <string>

namespace RawrXD {
namespace HexMag {

enum class ActionKind : uint32_t {
    ReadFile = 1,
    Search,
    Edit,
    Build,
    Run,
    Test,
    InspectBinary,
    Verify,
    AskUser,   // informational deficit — never fabricate
};

struct Action {
    ActionKind kind = ActionKind::Verify;
    std::string target;
    std::string payload;
};

enum class ClaimFinalizeClass : uint32_t {
    Proven = 1,
    Verified,
    DerivedFromGivenInput,
    ObservedFromLocalExecution,
    // Everything else is a state-machine violation if emitted as fact:
    Unknown,
    MissingInput,
    Unverified,
    Contradicted,
};

inline bool isAllowedFinalClaim(ClaimFinalizeClass c) {
    return c == ClaimFinalizeClass::Proven
        || c == ClaimFinalizeClass::Verified
        || c == ClaimFinalizeClass::DerivedFromGivenInput
        || c == ClaimFinalizeClass::ObservedFromLocalExecution;
}

} // namespace HexMag
} // namespace RawrXD
