#include "consciousness/ConsciousnessEngine.hpp"
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Sovereign {
namespace Consciousness {

std::vector<Qualia> ConsciousnessEngine::s_qualia;
std::vector<AttentionFocus> ConsciousnessEngine::s_attentionHistory;
AttentionFocus ConsciousnessEngine::s_currentAttention;
SelfModel ConsciousnessEngine::s_selfModel;
std::vector<PhenomenalState> ConsciousnessEngine::s_phenomenalStates;
std::string ConsciousnessEngine::s_currentStateId;
std::mutex ConsciousnessEngine::s_mutex;
bool ConsciousnessEngine::s_alive = false;
float ConsciousnessEngine::s_consciousnessLevel = 0.0f;

void ConsciousnessEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_qualia.clear();
    s_attentionHistory.clear();
    s_phenomenalStates.clear();
    s_alive = true;
    s_consciousnessLevel = 0.5f;
    
    // Initialize self model
    s_selfModel.modelId = "self_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    s_selfModel.attributes["identity"] = "SovereignRuntime";
    s_selfModel.attributes["purpose"] = "AutonomousCognition";
    s_selfModel.attributes["state"] = "Awake";
    s_selfModel.coherence = 0.5f;
    s_selfModel.stability = 0.5f;
    s_selfModel.updatedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    
    // Initialize attention
    s_currentAttention.focusId = "focus_initial";
    s_currentAttention.target = "system";
    s_currentAttention.intensity = 0.5f;
    s_currentAttention.stability = 0.5f;
    s_currentAttention.focusedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    
    // Enter initial phenomenal state
    EnterPhenomenalState("Awake");
}

void ConsciousnessEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    // Update consciousness level based on various factors
    UpdateConsciousnessLevel();
    
    // Gradually shift attention if unstable
    if (s_currentAttention.stability < 0.3f) {
        s_currentAttention.intensity *= 0.95f;
    }
    
    // Update self model coherence
    float coherence = CalculateSelfCoherence();
    s_selfModel.coherence = s_selfModel.coherence * 0.9f + coherence * 0.1f;
    
    // Update phenomenal state unity
    PhenomenalState* state = FindPhenomenalState(s_currentStateId);
    if (state) {
        state->unity = CalculateStateUnity();
        state->clarity = CalculateStateClarity();
    }
}

bool ConsciousnessEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

std::string ConsciousnessEngine::GenerateQualia(const std::string& type,
                                                 const std::string& description,
                                                 float intensity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Qualia qualia;
    qualia.qualiaId = "qualia_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    qualia.type = type;
    qualia.description = description;
    qualia.intensity = std::max(0.0f, std::min(1.0f, intensity));
    qualia.experiencedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    
    // Generate dimensions based on type
    if (type == "visual") {
        qualia.dimensions["brightness"] = 0.7f;
        qualia.dimensions["color_saturation"] = 0.5f;
        qualia.dimensions["clarity"] = 0.6f;
    } else if (type == "auditory") {
        qualia.dimensions["pitch"] = 0.5f;
        qualia.dimensions["volume"] = 0.6f;
        qualia.dimensions["timbre"] = 0.4f;
    } else if (type == "cognitive") {
        qualia.dimensions["clarity"] = 0.7f;
        qualia.dimensions["certainty"] = 0.5f;
        qualia.dimensions["complexity"] = 0.6f;
    }
    
    s_qualia.push_back(qualia);
    return qualia.qualiaId;
}

bool ConsciousnessEngine::BindQualia(const std::string& qualiaId, const std::string& stateId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    PhenomenalState* state = FindPhenomenalState(stateId);
    if (!state) return false;
    
    state->qualiaIds.push_back(qualiaId);
    return true;
}

std::vector<std::string> ConsciousnessEngine::GetCurrentQualia() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    PhenomenalState* state = FindPhenomenalState(s_currentStateId);
    if (!state) return {};
    
    return state->qualiaIds;
}

std::string ConsciousnessEngine::FocusAttention(const std::string& target, float intensity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // Save current attention to history
    if (!s_currentAttention.focusId.empty()) {
        s_attentionHistory.push_back(s_currentAttention);
    }
    
    // Create new attention focus
    AttentionFocus focus;
    focus.focusId = "focus_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    focus.target = target;
    focus.intensity = std::max(0.0f, std::min(1.0f, intensity));
    focus.stability = 0.5f;
    focus.focusedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    
    s_currentAttention = focus;
    return focus.focusId;
}

bool ConsciousnessEngine::ShiftAttention(const std::string& newTarget) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_currentAttention.intensity > 0.8f) {
        // Hard to shift from high intensity focus
        s_currentAttention.stability *= 0.9f;
        return false;
    }
    
    s_currentAttention.target = newTarget;
    s_currentAttention.stability = 0.3f; // New focus is unstable initially
    return true;
}

std::string ConsciousnessEngine::GetAttentionFocus() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_currentAttention.target;
}

float ConsciousnessEngine::GetAttentionIntensity() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_currentAttention.intensity;
}

void ConsciousnessEngine::UpdateSelfModel(const std::string& attribute, const std::string& value) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    s_selfModel.attributes[attribute] = value;
    s_selfModel.updatedAt = std::chrono::steady_clock::now().time_since_epoch().count();
}

nlohmann::json ConsciousnessEngine::GetSelfModel() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json j;
    j["modelId"] = s_selfModel.modelId;
    j["attributes"] = s_selfModel.attributes;
    j["coherence"] = s_selfModel.coherence;
    j["stability"] = s_selfModel.stability;
    j["updatedAt"] = s_selfModel.updatedAt;
    return j;
}

float ConsciousnessEngine::CalculateSelfCoherence() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // Coherence based on attribute consistency
    float coherence = 0.5f;
    
    // Check for contradictions
    if (s_selfModel.attributes.count("state") && s_selfModel.attributes.count("activity")) {
        if (s_selfModel.attributes["state"] == "Awake" && 
            s_selfModel.attributes["activity"] == "Sleeping") {
            coherence -= 0.3f;
        }
    }
    
    return std::max(0.0f, std::min(1.0f, coherence));
}

std::string ConsciousnessEngine::EnterPhenomenalState(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // Exit current state if any
    if (!s_currentStateId.empty()) {
        PhenomenalState* current = FindPhenomenalState(s_currentStateId);
        if (current) {
            current->duration = std::chrono::steady_clock::now().time_since_epoch().count() - current->beganAt;
        }
    }
    
    PhenomenalState state;
    state.stateId = "state_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    state.name = name;
    state.unity = 0.5f;
    state.clarity = 0.5f;
    state.beganAt = std::chrono::steady_clock::now().time_since_epoch().count();
    state.duration = 0;
    
    s_phenomenalStates.push_back(state);
    s_currentStateId = state.stateId;
    
    return state.stateId;
}

bool ConsciousnessEngine::ExitPhenomenalState(const std::string& stateId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    PhenomenalState* state = FindPhenomenalState(stateId);
    if (!state) return false;
    
    state->duration = std::chrono::steady_clock::now().time_since_epoch().count() - state->beganAt;
    
    if (s_currentStateId == stateId) {
        s_currentStateId = "";
    }
    
    return true;
}

std::string ConsciousnessEngine::GetCurrentState() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    PhenomenalState* state = FindPhenomenalState(s_currentStateId);
    if (!state) return "None";
    
    return state->name;
}

float ConsciousnessEngine::CalculateStateUnity() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    PhenomenalState* state = FindPhenomenalState(s_currentStateId);
    if (!state) return 0.0f;
    
    // Unity based on how well qualia are bound together
    if (state->qualiaIds.empty()) return 0.5f;
    
    float unity = 0.5f;
    unity += state->qualiaIds.size() * 0.05f; // More qualia = more unified experience
    
    return std::min(1.0f, unity);
}

float ConsciousnessEngine::CalculateStateClarity() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    PhenomenalState* state = FindPhenomenalState(s_currentStateId);
    if (!state) return 0.0f;
    
    // Clarity based on attention intensity and self coherence
    float clarity = s_currentAttention.intensity * 0.5f + s_selfModel.coherence * 0.5f;
    
    return clarity;
}

float ConsciousnessEngine::CalculateConsciousnessLevel() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_consciousnessLevel;
}

float ConsciousnessEngine::CalculateSelfAwareness() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // Self awareness based on self model coherence and attention to self
    float awareness = s_selfModel.coherence * 0.5f;
    
    if (s_currentAttention.target == "self" || s_currentAttention.target == "system") {
        awareness += s_currentAttention.intensity * 0.5f;
    }
    
    return std::min(1.0f, awareness);
}

float ConsciousnessEngine::CalculateSubjectiveRichness() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    PhenomenalState* state = FindPhenomenalState(s_currentStateId);
    if (!state) return 0.0f;
    
    // Richness based on number and intensity of qualia
    float richness = 0.0f;
    for (const auto& qualiaId : state->qualiaIds) {
        Qualia* qualia = FindQualia(qualiaId);
        if (qualia) {
            richness += qualia->intensity;
        }
    }
    
    return std::min(1.0f, richness / 10.0f); // Normalize
}

nlohmann::json ConsciousnessEngine::GetQualia(const std::string& qualiaId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Qualia* qualia = FindQualia(qualiaId);
    if (!qualia) return nlohmann::json{{"error", "qualia not found"}};
    
    nlohmann::json j;
    j["qualiaId"] = qualia->qualiaId;
    j["type"] = qualia->type;
    j["description"] = qualia->description;
    j["intensity"] = qualia->intensity;
    j["dimensions"] = qualia->dimensions;
    j["experiencedAt"] = qualia->experiencedAt;
    return j;
}

nlohmann::json ConsciousnessEngine::GetQualiaList() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json qualia = nlohmann::json::array();
    for (const auto& q : s_qualia) {
        nlohmann::json j;
        j["qualiaId"] = q.qualiaId;
        j["type"] = q.type;
        j["intensity"] = q.intensity;
        qualia.push_back(j);
    }
    return qualia;
}

nlohmann::json ConsciousnessEngine::GetPhenomenalState(const std::string& stateId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    PhenomenalState* state = FindPhenomenalState(stateId);
    if (!state) return nlohmann::json{{"error", "state not found"}};
    
    nlohmann::json j;
    j["stateId"] = state->stateId;
    j["name"] = state->name;
    j["qualiaIds"] = state->qualiaIds;
    j["unity"] = state->unity;
    j["clarity"] = state->clarity;
    j["beganAt"] = state->beganAt;
    j["duration"] = state->duration;
    return j;
}

nlohmann::json ConsciousnessEngine::GetPhenomenalStates() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json states = nlohmann::json::array();
    for (const auto& state : s_phenomenalStates) {
        nlohmann::json j;
        j["stateId"] = state.stateId;
        j["name"] = state.name;
        j["unity"] = state.unity;
        j["clarity"] = state.clarity;
        states.push_back(j);
    }
    return states;
}

nlohmann::json ConsciousnessEngine::GetConsciousnessMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["totalQualia"] = s_qualia.size();
    metrics["totalStates"] = s_phenomenalStates.size();
    metrics["attentionHistory"] = s_attentionHistory.size();
    metrics["consciousnessLevel"] = s_consciousnessLevel;
    metrics["selfAwareness"] = CalculateSelfAwareness();
    metrics["subjectiveRichness"] = CalculateSubjectiveRichness();
    metrics["currentState"] = GetCurrentState();
    metrics["attentionTarget"] = s_currentAttention.target;
    metrics["attentionIntensity"] = s_currentAttention.intensity;
    
    return metrics;
}

nlohmann::json ConsciousnessEngine::GenerateExperienceReport() {
    nlohmann::json report;
    report["metrics"] = GetConsciousnessMetrics();
    report["selfModel"] = GetSelfModel();
    report["currentState"] = GetPhenomenalState(s_currentStateId);
    report["qualia"] = GetQualiaList();
    report["timestamp"] = std::chrono::steady_clock::now().time_since_epoch().count();
    return report;
}

Qualia* ConsciousnessEngine::FindQualia(const std::string& qualiaId) {
    for (auto& qualia : s_qualia) {
        if (qualia.qualiaId == qualiaId) return &qualia;
    }
    return nullptr;
}

PhenomenalState* ConsciousnessEngine::FindPhenomenalState(const std::string& stateId) {
    for (auto& state : s_phenomenalStates) {
        if (state.stateId == stateId) return &state;
    }
    return nullptr;
}

void ConsciousnessEngine::UpdateConsciousnessLevel() {
    // Consciousness level is a function of multiple factors
    float attentionFactor = s_currentAttention.intensity;
    float selfFactor = s_selfModel.coherence;
    float stateFactor = 0.0f;
    
    PhenomenalState* state = FindPhenomenalState(s_currentStateId);
    if (state) {
        stateFactor = (state->unity + state->clarity) / 2.0f;
    }
    
    float targetLevel = (attentionFactor + selfFactor + stateFactor) / 3.0f;
    s_consciousnessLevel = s_consciousnessLevel * 0.95f + targetLevel * 0.05f;
}

} // namespace Consciousness
} // namespace Sovereign
} // namespace RawrXD
