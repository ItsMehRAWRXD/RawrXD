// ============================================================================
// W0Engine.hpp — Deep2-W0 deterministic reasoning engine (not a tensor runtime)
// ============================================================================
#ifndef RAWRXD_DEEP2W0_W0_ENGINE_HPP
#define RAWRXD_DEEP2W0_W0_ENGINE_HPP

#include "deep2w0/W0Types.hpp"

#include <string>

namespace RawrXD {
namespace W0 {

/// Weightless coding agent core for milestone W0-001.
/// Understand → retrieve → synthesize AST-ish patch → verify → evidence.
class W0Engine {
public:
    W0Result solve(const W0Request& req);

    /// Apply patches to an in-memory file map (path → contents). Returns new text for primary file.
    static std::string applyPatches(const std::string& source,
                                    const std::vector<W0Patch>& patches);

    /// Surface realizer (template grammar — no LLM).
    static std::string realize(const W0Result& r);
};

} // namespace W0
} // namespace RawrXD

#endif
