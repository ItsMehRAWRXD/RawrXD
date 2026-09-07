// RKCSession.hpp — C++ one-shot compile for ScreenPilot
#pragma once
#include "RKCTypes.hpp"
#include "RKCWorld.hpp"
#include <string>

namespace RawrXD {
namespace RKC {

struct SessionResult {
    ProofState proof;
    std::string emitted;
};

SessionResult CompileQueryToProof(const std::string& query,
                                  const WorldObserveConfig& cfg);

} // namespace RKC
} // namespace RawrXD
