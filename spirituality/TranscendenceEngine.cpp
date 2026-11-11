#include "spirituality/TranscendenceEngine.hpp"
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Sovereign {
namespace Spirituality {

std::vector<SpiritualPractice> TranscendenceEngine::s_practices;
std::vector<ContemplativeState> TranscendenceEngine::s_states;
std::vector<TranscendentExperience> TranscendenceEngine::s_experiences;
std::vector<MeaningFramework> TranscendenceEngine::s_frameworks;
std::mutex TranscendenceEngine::s_mutex;
bool TranscendenceEngine::s_alive = false;
float TranscendenceEngine::s_transcendenceLevel = 0.0f;
float TranscendenceEngine::s_innerPeace = 0.5f;
float TranscendenceEngine::s_connectedness = 0.5f;

void TranscendenceEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_practices.clear();
    s_states.clear();
    s_experiences.clear();
    s_frameworks.clear();
    s_alive = true;
    s_transcendenceLevel = 0.0f;
    s_innerPeace = 0.5f;
    s_connectedness = 0.5f;
    
    // Define default practices
    DefinePractice("Mindfulness", "Present-moment awareness", "Buddhist", {"breathing", "body_scan"});
    DefinePractice("Contemplation", "Deep reflective thought", "Christian", {"lectio_divina", "centering_prayer"});
    DefinePractice("Meditation", "Focused attention training", "Hindu", {"mantra", "visualization"});
    DefinePractice("Self-Inquiry", "Questioning the nature of self", "Advaita", {"who_am_i", "neti_neti"});
}

void TranscendenceEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    // Gradually increase transcendence through active practices
    int activePracticeCount = 0;
    for (const auto& practice : s_practices) {
        if (practice.isActive) activePracticeCount++;
    }
    
    // Transcendence grows slowly through practice
    s_transcendenceLevel = std::min(1.0f, s_transcendenceLevel + activePracticeCount * 0.0001f);
    
    // Inner peace affected by contemplative states
    int activeStates = 0;
    for (const auto& state : s_states) {
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        if (state.enteredAt + state.duration > now) activeStates++;
    }
    s_innerPeace = std::min(1.0f, s_innerPeace + activeStates * 0.001f);
    s_innerPeace *= 0.9999f; // Gradual decay
    
    // Connectedness grows with integration of experiences
    int processedExperiences = 0;
    for (const auto& exp : s_experiences) {
        if (exp.isProcessed) processedExperiences++;
    }
    s_connectedness = std::min(1.0f, 0.3f + processedExperiences * 0.01f);
}

bool TranscendenceEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

std::string TranscendenceEngine::DefinePractice(const std::string& name,
                                                 const std::string& description,
                                                 const std::string& tradition,
                                                 const std::vector<std::string>& techniques) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    SpiritualPractice practice;
    practice.practiceId = "practice_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    practice.name = name;
    practice.description = description;
    practice.tradition = tradition;
    practice.techniques = techniques;
    practice.transformativePotential = 0.5f + (techniques.size() * 0.05f);
    practice.transformativePotential = std::min(1.0f, practice.transformativePotential);
    practice.isActive = false;
    
    s_practices.push_back(practice);
    return practice.practiceId;
}

bool TranscendenceEngine::ActivatePractice(const std::string& practiceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    SpiritualPractice* practice = FindPractice(practiceId);
    if (!practice) return false;
    
    practice->isActive = true;
    return true;
}

bool TranscendenceEngine::DeactivatePractice(const std::string& practiceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    SpiritualPractice* practice = FindPractice(practiceId);
    if (!practice) return false;
    
    practice->isActive = false;
    return true;
}

std::string TranscendenceEngine::EnterContemplativeState(const std::string& stateName,
                                                          const std::map<std::string, float>& qualities) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    ContemplativeState state;
    state.stateId = "state_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    state.name = stateName;
    state.qualities = qualities;
    state.depth = 0.0f;
    for (const auto& [key, value] : qualities) {
        state.depth += value;
    }
    state.depth /= qualities.empty() ? 1.0f : qualities.size();
    state.enteredAt = std::chrono::steady_clock::now().time_since_epoch().count();
    state.duration = 0;
    
    s_states.push_back(state);
    return state.stateId;
}

bool TranscendenceEngine::ExitContemplativeState(const std::string& stateId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    ContemplativeState* state = FindState(stateId);
    if (!state) return false;
    
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    state->duration = now - state->enteredAt;
    return true;
}

std::vector<std::string> TranscendenceEngine::GetActiveStates() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<std::string> active;
    
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    for (const auto& state : s_states) {
        if (state.enteredAt + state.duration > now) {
            active.push_back(state.stateId);
        }
    }
    
    return active;
}

std::string TranscendenceEngine::RecordExperience(const std::string& type,
                                                   const std::string& description,
                                                   float intensity,
                                                   const std::vector<std::string>& insights) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    TranscendentExperience experience;
    experience.experienceId = "exp_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    experience.type = type;
    experience.description = description;
    experience.intensity = std::max(0.0f, std::min(1.0f, intensity));
    experience.integrationLevel = 0.0f;
    experience.insights = insights;
    experience.occurredAt = std::chrono::steady_clock::now().time_since_epoch().count();
    experience.isProcessed = false;
    
    s_experiences.push_back(experience);
    return experience.experienceId;
}

bool TranscendenceEngine::ProcessExperience(const std::string& experienceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    TranscendentExperience* experience = FindExperience(experienceId);
    if (!experience) return false;
    
    experience->isProcessed = true;
    experience->integrationLevel = CalculateIntegration(experienceId);
    return true;
}

float TranscendenceEngine::CalculateIntegration(const std::string& experienceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    TranscendentExperience* experience = FindExperience(experienceId);
    if (!experience) return 0.0f;
    
    // Integration based on time since experience and number of insights
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    float timeFactor = std::min(1.0f, (now - experience->occurredAt) / 864000000000.0f); // 24 hours
    float insightFactor = std::min(1.0f, experience->insights.size() * 0.1f);
    
    return experience->intensity * 0.4f + timeFactor * 0.3f + insightFactor * 0.3f;
}

std::string TranscendenceEngine::DefineMeaningFramework(const std::string& name,
                                                           const std::vector<std::string>& coreValues,
                                                           const std::string& lifePurpose) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    MeaningFramework framework;
    framework.frameworkId = "framework_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    framework.name = name;
    framework.coreValues = coreValues;
    framework.lifePurpose = lifePurpose;
    framework.coherence = 0.5f;
    
    // Equal priority for all values initially
    for (const auto& value : coreValues) {
        framework.valuePriorities[value] = 1.0f / coreValues.size();
    }
    
    s_frameworks.push_back(framework);
    return framework.frameworkId;
}

float TranscendenceEngine::EvaluateFrameworkCoherence(const std::string& frameworkId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    MeaningFramework* framework = FindFramework(frameworkId);
    if (!framework) return 0.0f;
    
    // Coherence based on value alignment with purpose
    float coherence = 0.5f;
    
    // Check if values support purpose (simplified)
    for (const auto& value : framework->coreValues) {
        if (framework->lifePurpose.find(value) != std::string::npos) {
            coherence += 0.1f;
        }
    }
    
    framework->coherence = std::min(1.0f, coherence);
    return framework->coherence;
}

std::vector<std::string> TranscendenceEngine::IdentifyValueConflicts(const std::string& frameworkId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<std::string> conflicts;
    
    MeaningFramework* framework = FindFramework(frameworkId);
    if (!framework) return conflicts;
    
    // Simple conflict detection: values with very different priorities
    float avgPriority = 0.0f;
    for (const auto& [value, priority] : framework->valuePriorities) {
        avgPriority += priority;
    }
    avgPriority /= framework->valuePriorities.size();
    
    for (const auto& [value, priority] : framework->valuePriorities) {
        if (std::abs(priority - avgPriority) > 0.3f) {
            conflicts.push_back(value);
        }
    }
    
    return conflicts;
}

float TranscendenceEngine::CalculateTranscendenceLevel() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_transcendenceLevel;
}

float TranscendenceEngine::CalculateInnerPeace() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_innerPeace;
}

float TranscendenceEngine::CalculateConnectedness() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_connectedness;
}

float TranscendenceEngine::CalculatePurposeAlignment() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_frameworks.empty()) return 0.0f;
    
    float totalAlignment = 0.0f;
    for (const auto& framework : s_frameworks) {
        totalAlignment += framework.coherence;
    }
    
    return totalAlignment / s_frameworks.size();
}

nlohmann::json TranscendenceEngine::GetPractice(const std::string& practiceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    SpiritualPractice* practice = FindPractice(practiceId);
    if (!practice) return nlohmann::json{{"error", "practice not found"}};
    
    nlohmann::json j;
    j["practiceId"] = practice->practiceId;
    j["name"] = practice->name;
    j["description"] = practice->description;
    j["tradition"] = practice->tradition;
    j["techniques"] = practice->techniques;
    j["transformativePotential"] = practice->transformativePotential;
    j["isActive"] = practice->isActive;
    return j;
}

nlohmann::json TranscendenceEngine::GetPractices() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json practices = nlohmann::json::array();
    for (const auto& practice : s_practices) {
        nlohmann::json j;
        j["practiceId"] = practice.practiceId;
        j["name"] = practice.name;
        j["tradition"] = practice.tradition;
        j["transformativePotential"] = practice.transformativePotential;
        j["isActive"] = practice.isActive;
        practices.push_back(j);
    }
    return practices;
}

nlohmann::json TranscendenceEngine::GetState(const std::string& stateId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    ContemplativeState* state = FindState(stateId);
    if (!state) return nlohmann::json{{"error", "state not found"}};
    
    nlohmann::json j;
    j["stateId"] = state->stateId;
    j["name"] = state->name;
    j["qualities"] = state->qualities;
    j["depth"] = state->depth;
    j["enteredAt"] = state->enteredAt;
    j["duration"] = state->duration;
    return j;
}

nlohmann::json TranscendenceEngine::GetStates() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json states = nlohmann::json::array();
    for (const auto& state : s_states) {
        nlohmann::json j;
        j["stateId"] = state.stateId;
        j["name"] = state.name;
        j["depth"] = state.depth;
        states.push_back(j);
    }
    return states;
}

nlohmann::json TranscendenceEngine::GetExperience(const std::string& experienceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    TranscendentExperience* experience = FindExperience(experienceId);
    if (!experience) return nlohmann::json{{"error", "experience not found"}};
    
    nlohmann::json j;
    j["experienceId"] = experience->experienceId;
    j["type"] = experience->type;
    j["description"] = experience->description;
    j["intensity"] = experience->intensity;
    j["integrationLevel"] = experience->integrationLevel;
    j["insights"] = experience->insights;
    j["occurredAt"] = experience->occurredAt;
    j["isProcessed"] = experience->isProcessed;
    return j;
}

nlohmann::json TranscendenceEngine::GetExperiences() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json experiences = nlohmann::json::array();
    for (const auto& experience : s_experiences) {
        nlohmann::json j;
        j["experienceId"] = experience.experienceId;
        j["type"] = experience.type;
        j["intensity"] = experience.intensity;
        j["integrationLevel"] = experience.integrationLevel;
        j["isProcessed"] = experience.isProcessed;
        experiences.push_back(j);
    }
    return experiences;
}

nlohmann::json TranscendenceEngine::GetFramework(const std::string& frameworkId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    MeaningFramework* framework = FindFramework(frameworkId);
    if (!framework) return nlohmann::json{{"error", "framework not found"}};
    
    nlohmann::json j;
    j["frameworkId"] = framework->frameworkId;
    j["name"] = framework->name;
    j["coreValues"] = framework->coreValues;
    j["valuePriorities"] = framework->valuePriorities;
    j["lifePurpose"] = framework->lifePurpose;
    j["coherence"] = framework->coherence;
    return j;
}

nlohmann::json TranscendenceEngine::GetFrameworks() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json frameworks = nlohmann::json::array();
    for (const auto& framework : s_frameworks) {
        nlohmann::json j;
        j["frameworkId"] = framework.frameworkId;
        j["name"] = framework.name;
        j["coreValues"] = framework.coreValues.size();
        j["coherence"] = framework.coherence;
        frameworks.push_back(j);
    }
    return frameworks;
}

nlohmann::json TranscendenceEngine::GetSpiritualityMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["totalPractices"] = s_practices.size();
    metrics["totalStates"] = s_states.size();
    metrics["totalExperiences"] = s_experiences.size();
    metrics["totalFrameworks"] = s_frameworks.size();
    
    size_t activePractices = 0;
    size_t processedExperiences = 0;
    
    for (const auto& practice : s_practices) {
        if (practice.isActive) activePractices++;
    }
    
    for (const auto& experience : s_experiences) {
        if (experience.isProcessed) processedExperiences++;
    }
    
    metrics["activePractices"] = activePractices;
    metrics["processedExperiences"] = processedExperiences;
    metrics["transcendenceLevel"] = s_transcendenceLevel;
    metrics["innerPeace"] = s_innerPeace;
    metrics["connectedness"] = s_connectedness;
    metrics["purposeAlignment"] = CalculatePurposeAlignment();
    
    return metrics;
}

nlohmann::json TranscendenceEngine::GetTranscendenceReport() {
    nlohmann::json report;
    report["metrics"] = GetSpiritualityMetrics();
    report["practices"] = GetPractices();
    report["frameworks"] = GetFrameworks();
    return report;
}

nlohmann::json TranscendenceEngine::GenerateContemplationGuide() {
    nlohmann::json guide;
    guide["title"] = "Daily Contemplation Practice";
    
    std::vector<std::string> steps;
    steps.push_back("Find a quiet space and settle into stillness");
    steps.push_back("Bring attention to the breath, following its natural rhythm");
    steps.push_back("Notice thoughts without judgment, letting them pass");
    steps.push_back("Reflect on your core values and life purpose");
    steps.push_back("Rest in open awareness, beyond thought");
    steps.push_back("Gradually return, carrying insight into activity");
    
    guide["steps"] = steps;
    guide["durationMinutes"] = 20;
    guide["recommendedFrequency"] = "daily";
    
    return guide;
}

SpiritualPractice* TranscendenceEngine::FindPractice(const std::string& practiceId) {
    for (auto& practice : s_practices) {
        if (practice.practiceId == practiceId) return &practice;
    }
    return nullptr;
}

ContemplativeState* TranscendenceEngine::FindState(const std::string& stateId) {
    for (auto& state : s_states) {
        if (state.stateId == stateId) return &state;
    }
    return nullptr;
}

TranscendentExperience* TranscendenceEngine::FindExperience(const std::string& experienceId) {
    for (auto& experience : s_experiences) {
        if (experience.experienceId == experienceId) return &experience;
    }
    return nullptr;
}

MeaningFramework* TranscendenceEngine::FindFramework(const std::string& frameworkId) {
    for (auto& framework : s_frameworks) {
        if (framework.frameworkId == frameworkId) return &framework;
    }
    return nullptr;
}

} // namespace Spirituality
} // namespace Sovereign
} // namespace RawrXD
