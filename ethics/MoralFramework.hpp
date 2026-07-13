#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Ethics {

struct MoralPrinciple {
    std::string principleId;
    std::string name;
    std::string description;
    float weight;
    bool isActive;
};

struct EthicalDilemma {
    std::string dilemmaId;
    std::string description;
    std::vector<std::string> options;
    std::map<std::string, float> consequences;
    std::string resolvedOption;
    bool isResolved;
    int64_t createdAt;
};

struct MoralEvaluation {
    std::string evaluationId;
    std::string action;
    float utility;
    float deontologicalScore;
    float virtueScore;
    float overallScore;
    std::vector<std::string> affectedParties;
    int64_t evaluatedAt;
};

class MoralFramework {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();

    static std::string DefinePrinciple(const std::string& name, 
                                         const std::string& description,
                                         float weight);
    static bool UpdatePrincipleWeight(const std::string& principleId, float weight);
    static bool ActivatePrinciple(const std::string& principleId);
    static bool DeactivatePrinciple(const std::string& principleId);
    
    static std::string RegisterDilemma(const std::string& description,
                                          const std::vector<std::string>& options);
    static std::string ResolveDilemma(const std::string& dilemmaId,
                                       const std::string& chosenOption);
    
    static std::string EvaluateAction(const std::string& action,
                                       const std::vector<std::string>& affectedParties,
                                       const std::map<std::string, float>& consequences);
    
    static float CalculateUtility(const std::string& action, 
                                   const std::map<std::string, float>& consequences);
    static float CalculateDeontologicalScore(const std::string& action);
    static float CalculateVirtueScore(const std::string& action);
    
    static std::vector<std::string> GetConflictingPrinciples(const std::string& action);
    static std::vector<std::string> GetSupportingPrinciples(const std::string& action);
    
    static nlohmann::json GetPrinciple(const std::string& principleId);
    static nlohmann::json GetPrinciples();
    static nlohmann::json GetDilemma(const std::string& dilemmaId);
    static nlohmann::json GetDilemmas();
    static nlohmann::json GetEvaluation(const std::string& evaluationId);
    static nlohmann::json GetEvaluations();
    
    static nlohmann::json GetEthicsMetrics();
    static nlohmann::json GetMoralReport();

private:
    static std::vector<MoralPrinciple> s_principles;
    static std::vector<EthicalDilemma> s_dilemmas;
    static std::vector<MoralEvaluation> s_evaluations;
    static std::mutex s_mutex;
    static bool s_alive;
    
    static MoralPrinciple* FindPrinciple(const std::string& principleId);
    static EthicalDilemma* FindDilemma(const std::string& dilemmaId);
    static MoralEvaluation* FindEvaluation(const std::string& evaluationId);
};

} // namespace Ethics
} // namespace Sovereign
} // namespace RawrXD
