#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Consciousness {

struct Qualia {
    std::string qualiaId;
    std::string type;
    std::string description;
    float intensity;
    std::map<std::string, float> dimensions;
    int64_t experiencedAt;
};

struct AttentionFocus {
    std::string focusId;
    std::string target;
    float intensity;
    float stability;
    std::vector<std::string> competingStimuli;
    int64_t focusedAt;
};

struct SelfModel {
    std::string modelId;
    std::map<std::string, std::string> attributes;
    float coherence;
    float stability;
    int64_t updatedAt;
};

struct PhenomenalState {
    std::string stateId;
    std::string name;
    std::vector<std::string> qualiaIds;
    float unity;
    float clarity;
    int64_t beganAt;
    int64_t duration;
};

class ConsciousnessEngine {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();

    static std::string GenerateQualia(const std::string& type,
                                       const std::string& description,
                                       float intensity);
    static bool BindQualia(const std::string& qualiaId, const std::string& stateId);
    static std::vector<std::string> GetCurrentQualia();
    
    static std::string FocusAttention(const std::string& target, float intensity);
    static bool ShiftAttention(const std::string& newTarget);
    static std::string GetAttentionFocus();
    static float GetAttentionIntensity();
    
    static void UpdateSelfModel(const std::string& attribute, const std::string& value);
    static nlohmann::json GetSelfModel();
    static float CalculateSelfCoherence();
    
    static std::string EnterPhenomenalState(const std::string& name);
    static bool ExitPhenomenalState(const std::string& stateId);
    static std::string GetCurrentState();
    static float CalculateStateUnity();
    static float CalculateStateClarity();
    
    static float CalculateConsciousnessLevel();
    static float CalculateSelfAwareness();
    static float CalculateSubjectiveRichness();
    
    static nlohmann::json GetQualia(const std::string& qualiaId);
    static nlohmann::json GetQualiaList();
    static nlohmann::json GetPhenomenalState(const std::string& stateId);
    static nlohmann::json GetPhenomenalStates();
    
    static nlohmann::json GetConsciousnessMetrics();
    static nlohmann::json GenerateExperienceReport();

private:
    static std::vector<Qualia> s_qualia;
    static std::vector<AttentionFocus> s_attentionHistory;
    static AttentionFocus s_currentAttention;
    static SelfModel s_selfModel;
    static std::vector<PhenomenalState> s_phenomenalStates;
    static std::string s_currentStateId;
    static std::mutex s_mutex;
    static bool s_alive;
    static float s_consciousnessLevel;
    
    static Qualia* FindQualia(const std::string& qualiaId);
    static PhenomenalState* FindPhenomenalState(const std::string& stateId);
    static void UpdateConsciousnessLevel();
};

} // namespace Consciousness
} // namespace Sovereign
} // namespace RawrXD
