#include "SessionBinder.h"
#include <windows.h>

namespace RawrXD::Command {

SessionBinder& SessionBinder::instance() {
    static SessionBinder s;
    return s;
}

bool SessionBinder::bind(const SessionSnapshot& snap) {
    if (snap.workspaceRoot.empty()) return false;
    snap_ = snap;
    snap_.bound = true;
    if (snap_.machine.empty()) {
        char name[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD sz = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameA(name, &sz)) snap_.machine = name;
        else snap_.machine = "This PC";
    }
    return true;
}

void SessionBinder::clear() {
    snap_ = {};
}

std::string SessionBinder::diagnosticIfUnbound() const {
    if (snap_.bound) return {};
    return "COMMAND_SESSION_001: FAIL_CLOSED — session unbound. "
           "Select workspace and repository before starting an agent.";
}

}  // namespace RawrXD::Command
