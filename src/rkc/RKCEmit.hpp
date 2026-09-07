// RKCEmit.hpp — serialize ProofState (decision state, not RAG dump)
#pragma once
#include "RKCTypes.hpp"
#include <string>

namespace RawrXD {
namespace RKC {

std::string EmitState(const ProofState& proof);

} // namespace RKC
} // namespace RawrXD
