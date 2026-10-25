// ============================================================================
// agentic/HexMagAction.hpp — HEXMAG action surface
// ============================================================================
#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace HexMag {

enum class HexMagActionType : uint8_t {
    None = 0,
    Generate,
    Verify,
    Revise,
    Finalize,
    Abort,
};

struct HexMagAction {
    HexMagActionType type = HexMagActionType::None;
    std::string prompt;
    std::string context;
    std::string result;
    bool success = false;
    std::string error;
};

} // namespace HexMag
} // namespace RawrXD
