#pragma once
// Optional adapter for current RawrXD repository's src/agent/delegated_agents.hpp.
// Compile this only in the actual RawrXD agent target (linking delegated_agents.cpp).
#include "RawrSwarmEvents.hpp"
#include "agent/delegated_agents.hpp"

namespace rawr::live {
// Warning: onAgentStateChanged and onMessage are single-callback setters in this
// revision; use a fanout in the caller if some other subscriber already owns them.
void attachDelegationObserver(RawrXD::Delegation::DelegationManager& manager,Sink& sink);
}
