#pragma once
// COMMAND_HOME_001 — Remote control stub (EGRESS_BLOCKED until EGRESS_001 + STATIC_DEP_001)
#include <string>

namespace RawrXD::CommandHome {

inline constexpr const char* kRemoteBlockedDiagnostic =
    "REMOTE_CONTROL: EGRESS_BLOCKED — device pairing and control channel are not "
    "available until EGRESS_001 and STATIC_DEP_001 close.";

struct RemoteControlConfig {
    bool pairingEnabled = false;
    bool listenEnabled = false;
    uint16_t controlPort = 0;
};

inline bool RemoteControlAllowed() { return false; }

inline std::string RemoteControlStatus() { return kRemoteBlockedDiagnostic; }

inline bool TryStartControlListener(uint16_t /*port*/) { return false; }

inline bool TryPairDevice(const std::string& /*deviceId*/) { return false; }

inline void EmergencyStopAllAgents() { /* local broker handles stop in Phase 1 */ }

} // namespace RawrXD::CommandHome
