#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Knowledge {

struct Belief {
    std::string beliefId;
    std::string proposition;
    float confidence;
    std::vector<std::string> evidenceIds;
    std::string source;
    int64_t formedAt;
    int64_t lastUpdated;
    bool isActive;
};

struct Evidence {
    std::string evidenceId;
    std::string description;
    std::string type;
    float weight;
    bool supports;
    int64_t recordedAt;
    bool isActive;
};

struct Justification {
    std::string justificationId;
    std::string beliefId;
    std::string reasoning;
    std::vector<std::string> premiseIds;
    float coherenceScore;
    int64_t createdAt;
};

class EpistemologyEngine {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();

    static std::string FormBelief(const std::string& proposition,
                                   float initialConfidence,
                                   const std::string& source);
    static bool UpdateBeliefConfidence(const std::string& beliefId, float delta);
    static bool ReviseBelief(const std::string& beliefId, const std::string& newProposition);
    static bool RetractBelief(const std::string& beliefId);
    
    static std::string AddEvidence(const std::string& description,
                                    const std::string& type,
                                    float weight,
                                    bool supports);
    static bool AttachEvidence(const std::string& beliefId, const std::string& evidenceId);
    static bool DetachEvidence(const std::string& beliefId, const std::string& evidenceId);
    
    static std::string CreateJustification(const std::string& beliefId,
                                             const std::string& reasoning,
                                             const std::vector<std::string>& premiseIds);
    static float EvaluateCoherence(const std::string& beliefId);
    
    static std::vector<std::string> FindConflictingBeliefs(const std::string& beliefId);
    static std::vector<std::string> FindSupportingBeliefs(const std::string& beliefId);
    
    static nlohmann::json GetBelief(const std::string& beliefId);
    static nlohmann::json GetBeliefs();
    static nlohmann::json GetEvidence(const std::string& evidenceId);
    static nlohmann::json GetBeliefEvidence(const std::string& beliefId);
    static nlohmann::json GetJustification(const std::string& justificationId);
    
    static nlohmann::json QueryBeliefs(const std::string& query);
    static nlohmann::json GetEpistemologyMetrics();
    static nlohmann::json GetBeliefNetwork();

private:
    static std::vector<Belief> s_beliefs;
    static std::vector<Evidence> s_evidence;
    static std::vector<Justification> s_justifications;
    static std::mutex s_mutex;
    static bool s_alive;
    
    static Belief* FindBelief(const std::string& beliefId);
    static Evidence* FindEvidence(const std::string& evidenceId);
    static Justification* FindJustification(const std::string& justificationId);
    static void UpdateBeliefFromEvidence(Belief& belief);
};

} // namespace Knowledge
} // namespace Sovereign
} // namespace RawrXD
