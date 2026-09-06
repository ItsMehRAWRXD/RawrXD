#pragma once
#include <string>

namespace RawrXD::Command {

// Phase 5 stub — no network listen until REMOTE_CONTROL_001 + EGRESS_001.
class IControlChannel {
public:
    virtual ~IControlChannel() = default;
    virtual bool isEnabled() const { return false; }
    virtual bool startListening() { return false; }
    virtual void stopListening() {}
};

class DisabledControlChannel final : public IControlChannel {};

inline IControlChannel& controlChannel() {
    static DisabledControlChannel ch;
    return ch;
}

}  // namespace RawrXD::Command
