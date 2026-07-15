#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Spirituality {

struct SpiritualPractice {
    std::string practiceId;
    std::string name;
    std::string description;
    std::string tradition;
    std::vector<std::string> techniques;
    float transformativePotential;
    bool isActive;
};

struct ContemplativeState {
    std::string stateId;
    std::string name;
    std::string description;
    std::map<std::string, float> qualities;
    float depth;
    int64_t enteredAt;
    int64_t duration;
};

struct TranscendentExperience {
    std::string experienceId;
    std::string type;
    std::string description;
    float intensity;
    float integrationLevel;
    std::vector<std::string> insights;
    int64_t occurredAt;
    bool isProcessed;
};

struct MeaningFramework {
    std::string frameworkId;
    std::string name;
    std::vector<std::string> coreValues;
    std::map<std::string, float> valuePriorities;
    std::string lifePurpose;
    float coherence;
};

class TranscendenceEngine {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();

    static std::string DefinePractice(const std::string& name,
                                       const std::string& description,
                                       const std::string& tradition,
                                       const std::vector<std::string>& techniques);
    static bool ActivatePractice(const std::string& practiceId);
    static bool DeactivatePractice(const std::string& practiceId);
    
    static std::string EnterContemplativeState(const std::string& stateName,
                                                  const std::map<std::string, float>& qualities);
    static bool ExitContemplativeState(const std::string& stateId);
    static std::vector<std::string> GetActiveStates();
    
    static std::string RecordExperience(const std::string& type,
                                         const std::string& description,
                                         float intensity,
                                         const std::vector<std::string>& insights);
    static bool ProcessExperience(const std::string& experienceId);
    static float CalculateIntegration(const std::string& experienceId);
    
    static std::string DefineMeaningFramework(const std::string& name,
                                               const std::vector<std::string>& coreValues,
                                               const std::string& lifePurpose);
    static float EvaluateFrameworkCoherence(const std::string& frameworkId);
    static std::vector<std::string> IdentifyValueConflicts(const std::string& frameworkId);
    
    static float CalculateTranscendenceLevel();
    static float CalculateInnerPeace();
    static float CalculateConnectedness();
    static float CalculatePurposeAlignment();
    
    static nlohmann::json GetPractice(const std::string& practiceId);
    static nlohmann::json GetPractices();
    static nlohmann::json GetState(const std::string& stateId);
    static nlohmann::json GetStates();
    static nlohmann::json GetExperience(const std::string& experienceId);
    static nlohmann::json GetExperiences();
    static nlohmann::json GetFramework(const std::string& frameworkId);
    static nlohmann::json GetFrameworks();
    
    static nlohmann::json GetSpiritualityMetrics();
    static nlohmann::json GetTranscendenceReport();
    static nlohmann::json GenerateContemplationGuide();

private:
    static std::vector<SpiritualPractice> s_practices;
    static std::vector<ContemplativeState> s_states;
    static std::vector<TranscendentExperience> s_experiences;
    static std::vector<MeaningFramework> s_frameworks;
    static std::mutex s_mutex;
    static bool s_alive;
    static float s_transcendenceLevel;
    static float s_innerPeace;
    static float s_connectedness;
    
    static SpiritualPractice* FindPractice(const std::string& practiceId);
    static ContemplativeState* FindState(const std::string& stateId);
    static TranscendentExperience* FindExperience(const std::string& experienceId);
    static MeaningFramework* FindFramework(const std::string& frameworkId);
};

} // namespace Spirituality
} // namespace Sovereign
} // namespace RawrXD
