// Win32IDE_SwarmModelSelector.h — Local swarm model inventory + N=1..16 orch plan
#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace Win32App {

constexpr unsigned kSwarmOrchCap = 16;

struct SwarmModelOrchPlan {
    unsigned taskCount = 0;     // 1..16 after resolve; 0 = fail-closed
    unsigned maxParallel = 1;   // 1..taskCount
    bool sequential = false;
    bool emptyFailClosed = true;
    std::vector<std::string> models; // selected local paths / tags (no fakes)
};

/// Append reachable local Ollama /api/tags names (127.0.0.1:11434). No-op if down.
void appendLocalOllamaHttpTags(std::vector<std::string>& out, unsigned maxEntries);

/// Multi-root GGUF + Ollama /api/tags (when reachable) + filesystem manifests.
/// Fail-closed: empty vector if none found (never invent models).
std::vector<std::string> enumerateSwarmModelCandidates(unsigned maxEntries = 512);

/// Cap N at 16 and at inventory size. Env: RAWRXD_SWARM_N, RAWRXD_SWARM_MAX_PARALLEL,
/// RAWRXD_SWARM_SEQUENTIAL=1. Empty inventory => taskCount=0.
SwarmModelOrchPlan resolveSwarmModelOrchPlan(unsigned requestedN = 0);

} // namespace Win32App
} // namespace RawrXD
