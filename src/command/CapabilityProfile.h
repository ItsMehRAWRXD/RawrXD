#pragma once
#include <cstdint>
#include <string>

namespace RawrXD::Command {

enum Capability : uint32_t {
    CapRead        = 1u << 0,
    CapEdit        = 1u << 1,
    CapExecute     = 1u << 2,
    CapCommit      = 1u << 3,
    CapPush        = 1u << 4,
    CapDestructive = 1u << 5,
};

inline uint32_t defaultLocalProfile() {
    return CapRead | CapEdit | CapExecute;
}

inline bool hasCap(uint32_t profile, Capability c) {
    return (profile & static_cast<uint32_t>(c)) != 0;
}

const char* capabilityName(Capability c);

}  // namespace RawrXD::Command
