#pragma once
#include "CapabilityProfile.h"
#include <string>

namespace RawrXD::Command {

struct SessionSnapshot {
    std::string machine;
    std::string workspaceRoot;
    std::string repository;
    std::string branch;
    std::string model = "Deep2 Local";
    uint32_t capabilities = defaultLocalProfile();
    bool bound = false;
};

class SessionBinder {
public:
    static SessionBinder& instance();

    bool bind(const SessionSnapshot& snap);
    void clear();
    bool isBound() const { return snap_.bound; }
    const SessionSnapshot& snapshot() const { return snap_; }

    std::string diagnosticIfUnbound() const;

private:
    SessionSnapshot snap_{};
};

}  // namespace RawrXD::Command
