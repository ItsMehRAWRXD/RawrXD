#include "CapabilityProfile.h"

namespace RawrXD::Command {

const char* capabilityName(Capability c) {
    switch (c) {
    case CapRead: return "read";
    case CapEdit: return "edit";
    case CapExecute: return "execute";
    case CapCommit: return "commit";
    case CapPush: return "push";
    case CapDestructive: return "destructive";
    default: return "unknown";
    }
}

}  // namespace RawrXD::Command
