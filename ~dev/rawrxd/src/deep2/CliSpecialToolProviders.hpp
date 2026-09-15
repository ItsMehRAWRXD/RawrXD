#pragma once
#include "AgentToolRegistry.hpp"

#include <stdexcept>
#include <utility>

namespace RawrXD::Agentic {

struct CliSpecialToolProviders {
    AgentToolRegistry::Handler ssa_lift;
    AgentToolRegistry::Handler byte_patch;
    AgentToolRegistry::Handler memory_patch;
};

// Adapter only: callers pass lambdas that invoke the EXISTING CLI implementations.
// No SSA/patch implementation is duplicated here.
inline void RegisterCliSpecialToolProviders(
    AgentToolRegistry& authority,
    CliSpecialToolProviders providers) {

    auto register_one = [&authority](
        ToolDescriptor descriptor,
        AgentToolRegistry::Handler handler) {

        if (!handler) return;
        if (authority.contains(descriptor.id)) return;

        try {
            authority.registerTool(std::move(descriptor), std::move(handler));
        } catch (const std::invalid_argument&) {
            // Another surface may have concurrently registered the same canonical tool.
            if (!authority.contains(descriptor.id)) throw;
        }
    };

    register_one(
        {"ssa-lift", {"ssa_lift", "SSALift"}, "Lift code/bytes into the existing CLI SSA pipeline."},
        std::move(providers.ssa_lift));

    register_one(
        {"byte-patch", {"byte_patch", "BytePatch"}, "Apply a patch through the existing CLI byte-patch provider."},
        std::move(providers.byte_patch));

    register_one(
        {"memory-patch", {"memory_patch", "MemoryPatch"}, "Apply a patch through the existing CLI memory-patch provider."},
        std::move(providers.memory_patch));
}

} // namespace RawrXD::Agentic
