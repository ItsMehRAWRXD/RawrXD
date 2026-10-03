#pragma once
#include <cstdint>
#include <string>

namespace rawrxd { namespace agentic {

enum class HexMagActionType : uint32_t {
    None = 0,
    Analyze,
    Patch,
    Verify,
    Commit
};

struct HexMagAction {
    HexMagActionType type = HexMagActionType::None;
    std::string target;
    uint32_t flags = 0;
    bool validate() const { return type != HexMagActionType::None && !target.empty(); }
};

}} // namespace rawrxd::agentic
