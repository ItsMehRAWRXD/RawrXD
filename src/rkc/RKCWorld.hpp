// RKCWorld.hpp — facade over W0 GraphStore + REAL observers
#pragma once
#include "RKCTypes.hpp"
#include "deep2w0/W0GraphStore.hpp"
#include <string>
#include <unordered_map>

namespace RawrXD {
namespace RKC {

struct WorldObserveConfig {
    std::string modelPath;     // file or shard directory
    uint64_t availableVram = 0;
    uint64_t weightsBytes = 0;
    uint64_t kvBudget = 0;
    uint64_t forwardArena = 0;
    uint64_t safetyMargin = (512ull << 20);
    bool probeOllama11434 = true;
};

class World {
public:
    void clearSession();
    void putAtom(const KnowledgeAtom& a);
    const KnowledgeAtom* get(const std::string& key) const;
    void observeFilesystem(const WorldObserveConfig& cfg);
    void observeLivePath();
    void observeHardware(const WorldObserveConfig& cfg);
    void observeNegative(const WorldObserveConfig& cfg);
    void observeAbsence(const WorldObserveConfig& cfg, const std::string& repoRoot);
    void observeCodeWorld(const std::string& repoRoot);
    void observeModelInventory(const std::string& modelRoot);
    void seedAll(const WorldObserveConfig& cfg);

    W0::GraphStore& graph() { return graph_; }
    const std::unordered_map<std::string, KnowledgeAtom>& atoms() const {
        return atoms_;
    }

private:
    void putReal(const std::string& key, const std::string& value,
                 const std::string& source);
    void putNeg(const std::string& key, EpistemicState neg,
                const std::string& value, const std::string& source);

    W0::GraphStore graph_;
    std::unordered_map<std::string, KnowledgeAtom> atoms_;
};

} // namespace RKC
} // namespace RawrXD
