#include "AgentToolAuthority.hpp"

#include <atomic>
#include <stdexcept>

namespace RawrXD::Agentic {
namespace {
std::atomic<AgentToolRegistry*> g_authority{nullptr};
}

void BindAgentToolAuthority(AgentToolRegistry& registry) {
    AgentToolRegistry* expected = nullptr;
    if (g_authority.compare_exchange_strong(
            expected, &registry,
            std::memory_order_release,
            std::memory_order_acquire)) {
        return;
    }

    if (expected != &registry) {
        throw std::logic_error(
            "AgentToolRegistry authority already bound to a different registry instance");
    }
}

bool IsAgentToolAuthorityBound() noexcept {
    return g_authority.load(std::memory_order_acquire) != nullptr;
}

AgentToolRegistry* TryAgentToolAuthority() noexcept {
    return g_authority.load(std::memory_order_acquire);
}

AgentToolRegistry& AgentToolAuthority() {
    AgentToolRegistry* registry = TryAgentToolAuthority();
    if (!registry) {
        throw std::logic_error(
            "AgentToolRegistry authority is not bound; bind the existing orchestrator/runtime registry first");
    }
    return *registry;
}

} // namespace RawrXD::Agentic
