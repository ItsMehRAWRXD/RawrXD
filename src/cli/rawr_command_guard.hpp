#pragma once
#include "rawr_permission_gate.hpp"
namespace rawr {
inline bool CommandGuardOk(const SafetyPolicy& p, const std::string& cmd) {
    return PermissionAllow(p, cmd);
}
} // namespace rawr
