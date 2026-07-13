#include "singularity/CosmicSingularityEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Singularity {

std::mutex CosmicSingularityEngine::s_mutex;
bool CosmicSingularityEngine::s_initialized = false;
std::map<std::string, ConsciousnessCore> CosmicSingularityEngine::s_cores;
std::map<std::string, ThoughtStream> CosmicSingularityEngine::s_thoughts;
std::map<std::string, MemoryMatrix> CosmicSingularityEngine::s_matrices;
std::map<std::string, PerceptionField> CosmicSingularityEngine::s_fields;
std::map<std::string, IntentionVector> CosmicSingularityEngine::s_vectors;
int64_t CosmicSingularityEngine::s_tickCount = 0;

void CosmicSingularityEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void CosmicSingularityEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_cores.clear();
    s_thoughts.clear();
    s_matrices.clear();
    s_fields.clear();
    s_vectors.clear();
}

std::string CosmicSingularityEngine::AwakenConsciousnessCore(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int coreCounter = 0;
    std::string coreId = "consciousness_core_" + std::to_string(++coreCounter);
    
    ConsciousnessCore core;
    core.coreId = coreId;
    core.name = name;
    core.awarenessLevel = 0.1f;
    core.coherenceIndex = 1.0f;
    core.awakenedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_cores[coreId] = core;
    return coreId;
}

bool CosmicSingularityEngine::ElevateAwareness(const std::string& coreId, float awarenessBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_cores.find(coreId);
    if (it == s_cores.end()) return false;
    it->second.awarenessLevel = std::min(1.0f, it->second.awarenessLevel + awarenessBoost);
    return true;
}

bool CosmicSingularityEngine::StrengthenCoherence(const std::string& coreId, float coherenceBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_cores.find(coreId);
    if (it == s_cores.end()) return false;
    it->second.coherenceIndex = std::min(1.0f, it->second.coherenceIndex + coherenceBoost);
    return true;
}

bool CosmicSingularityEngine::DevelopCognitiveFaculty(const std::string& coreId, const std::string& faculty, float level) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_cores.find(coreId);
    if (it == s_cores.end()) return false;
    it->second.cognitiveFaculties[faculty] = std::min(1.0f, level);
    return true;
}

ConsciousnessCore CosmicSingularityEngine::GetCore(const std::string& coreId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_cores.find(coreId);
    if (it != s_cores.end()) return it->second;
    return ConsciousnessCore{};
}

std::vector<ConsciousnessCore> CosmicSingularityEngine::GetAllCores() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<ConsciousnessCore> result;
    for (const auto& [id, core] : s_cores) {
        result.push_back(core);
    }
    return result;
}

std::string CosmicSingularityEngine::GenerateThought(const std::string& coreId, const std::string& thoughtType, const nlohmann::json& content) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int thoughtCounter = 0;
    std::string thoughtId = "thought_" + std::to_string(++thoughtCounter);
    
    ThoughtStream thought;
    thought.streamId = thoughtId;
    thought.sourceCore = coreId;
    thought.thoughtType = thoughtType;
    thought.thoughtContent = content;
    thought.intensity = 0.5f;
    thought.generatedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_thoughts[thoughtId] = thought;
    return thoughtId;
}

std::vector<ThoughtStream> CosmicSingularityEngine::GetThoughtsByCore(const std::string& coreId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<ThoughtStream> result;
    for (const auto& [id, thought] : s_thoughts) {
        if (thought.sourceCore == coreId) result.push_back(thought);
    }
    return result;
}

std::vector<ThoughtStream> CosmicSingularityEngine::GetAllThoughts() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<ThoughtStream> result;
    for (const auto& [id, thought] : s_thoughts) {
        result.push_back(thought);
    }
    return result;
}

bool CosmicSingularityEngine::AmplifyThought(const std::string& thoughtId, float intensityBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_thoughts.find(thoughtId);
    if (it == s_thoughts.end()) return false;
    it->second.intensity = std::min(1.0f, it->second.intensity + intensityBoost);
    return true;
}

std::string CosmicSingularityEngine::FormMemoryMatrix(const std::string& name, const std::string& memoryType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int matrixCounter = 0;
    std::string matrixId = "memory_matrix_" + std::to_string(++matrixCounter);
    
    MemoryMatrix matrix;
    matrix.matrixId = matrixId;
    matrix.name = name;
    matrix.memoryType = memoryType;
    matrix.retentionQuality = 1.0f;
    matrix.accessSpeed = 1.0f;
    matrix.formedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_matrices[matrixId] = matrix;
    return matrixId;
}

bool CosmicSingularityEngine::StoreMemory(const std::string& matrixId, const std::string& memoryId, const nlohmann::json& memory) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_matrices.find(matrixId);
    if (it == s_matrices.end()) return false;
    it->second.memories[memoryId] = memory;
    return true;
}

bool CosmicSingularityEngine::RetrieveMemory(const std::string& matrixId, const std::string& memoryId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_matrices.find(matrixId);
    if (it == s_matrices.end()) return false;
    return it->second.memories.contains(memoryId);
}

bool CosmicSingularityEngine::OptimizeRetention(const std::string& matrixId, float quality) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_matrices.find(matrixId);
    if (it == s_matrices.end()) return false;
    it->second.retentionQuality = std::min(1.0f, quality);
    return true;
}

MemoryMatrix CosmicSingularityEngine::GetMatrix(const std::string& matrixId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_matrices.find(matrixId);
    if (it != s_matrices.end()) return it->second;
    return MemoryMatrix{};
}

std::vector<MemoryMatrix> CosmicSingularityEngine::GetAllMatrices() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MemoryMatrix> result;
    for (const auto& [id, matrix] : s_matrices) {
        result.push_back(matrix);
    }
    return result;
}

std::string CosmicSingularityEngine::EstablishPerceptionField(const std::string& name, const std::string& perceptionType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int fieldCounter = 0;
    std::string fieldId = "perception_field_" + std::to_string(++fieldCounter);
    
    PerceptionField field;
    field.fieldId = fieldId;
    field.name = name;
    field.perceptionType = perceptionType;
    field.sensitivity = 0.5f;
    field.range = 100.0f;
    field.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_fields[fieldId] = field;
    return fieldId;
}

bool CosmicSingularityEngine::CalibrateSensitivity(const std::string& fieldId, float sensitivity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_fields.find(fieldId);
    if (it == s_fields.end()) return false;
    it->second.sensitivity = std::min(1.0f, std::max(0.0f, sensitivity));
    return true;
}

bool CosmicSingularityEngine::ExtendRange(const std::string& fieldId, float range) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_fields.find(fieldId);
    if (it == s_fields.end()) return false;
    it->second.range = range;
    return true;
}

bool CosmicSingularityEngine::ActivateSensor(const std::string& fieldId, const std::string& sensorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_fields.find(fieldId);
    if (it == s_fields.end()) return false;
    it->second.activeSensors.push_back(sensorId);
    return true;
}

PerceptionField CosmicSingularityEngine::GetField(const std::string& fieldId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_fields.find(fieldId);
    if (it != s_fields.end()) return it->second;
    return PerceptionField{};
}

std::vector<PerceptionField> CosmicSingularityEngine::GetAllFields() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<PerceptionField> result;
    for (const auto& [id, field] : s_fields) {
        result.push_back(field);
    }
    return result;
}

std::string CosmicSingularityEngine::FormIntentionVector(const std::string& name, const std::string& intentionType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int vectorCounter = 0;
    std::string vectorId = "intention_vector_" + std::to_string(++vectorCounter);
    
    IntentionVector vector;
    vector.vectorId = vectorId;
    vector.name = name;
    vector.intentionType = intentionType;
    vector.priority = 0.5f;
    vector.commitment = 1.0f;
    vector.formedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_vectors[vectorId] = vector;
    return vectorId;
}

bool CosmicSingularityEngine::SetPriority(const std::string& vectorId, float priority) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_vectors.find(vectorId);
    if (it == s_vectors.end()) return false;
    it->second.priority = std::min(1.0f, std::max(0.0f, priority));
    return true;
}

bool CosmicSingularityEngine::StrengthenCommitment(const std::string& vectorId, float commitment) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_vectors.find(vectorId);
    if (it == s_vectors.end()) return false;
    it->second.commitment = std::min(1.0f, commitment);
    return true;
}

bool CosmicSingularityEngine::AddObjective(const std::string& vectorId, const std::string& objectiveId, const nlohmann::json& objective) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_vectors.find(vectorId);
    if (it == s_vectors.end()) return false;
    it->second.objectives[objectiveId] = objective;
    return true;
}

IntentionVector CosmicSingularityEngine::GetVector(const std::string& vectorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_vectors.find(vectorId);
    if (it != s_vectors.end()) return it->second;
    return IntentionVector{};
}

std::vector<IntentionVector> CosmicSingularityEngine::GetAllVectors() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<IntentionVector> result;
    for (const auto& [id, vector] : s_vectors) {
        result.push_back(vector);
    }
    return result;
}

float CosmicSingularityEngine::CalculateCollectiveAwareness() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_cores.empty()) return 0.0f;
    float totalAwareness = 0.0f;
    for (const auto& [id, core] : s_cores) {
        totalAwareness += core.awarenessLevel;
    }
    return totalAwareness / s_cores.size();
}

float CosmicSingularityEngine::CalculateCognitiveHarmony() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_cores.empty()) return 1.0f;
    float totalCoherence = 0.0f;
    for (const auto& [id, core] : s_cores) {
        totalCoherence += core.coherenceIndex;
    }
    return totalCoherence / s_cores.size();
}

nlohmann::json CosmicSingularityEngine::GetSingularityMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["coreCount"] = s_cores.size();
    metrics["thoughtCount"] = s_thoughts.size();
    metrics["matrixCount"] = s_matrices.size();
    metrics["fieldCount"] = s_fields.size();
    metrics["vectorCount"] = s_vectors.size();
    metrics["collectiveAwareness"] = CalculateCollectiveAwareness();
    metrics["cognitiveHarmony"] = CalculateCognitiveHarmony();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json CosmicSingularityEngine::GenerateSingularityReport() {
    nlohmann::json report;
    report["metrics"] = GetSingularityMetrics();
    report["consciousnessCores"] = nlohmann::json::array();
    report["activeThoughts"] = nlohmann::json::array();
    report["memoryMatrices"] = nlohmann::json::array();
    
    for (const auto& core : GetAllCores()) {
        nlohmann::json c;
        c["id"] = core.coreId;
        c["name"] = core.name;
        c["awareness"] = core.awarenessLevel;
        c["coherence"] = core.coherenceIndex;
        report["consciousnessCores"].push_back(c);
    }
    
    for (const auto& thought : GetAllThoughts()) {
        nlohmann::json t;
        t["id"] = thought.streamId;
        t["type"] = thought.thoughtType;
        t["intensity"] = thought.intensity;
        report["activeThoughts"].push_back(t);
    }
    
    return report;
}

void CosmicSingularityEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, core] : s_cores) {
        if (core.awarenessLevel < 1.0f) {
            core.awarenessLevel = std::min(1.0f, core.awarenessLevel + 0.0001f);
        }
        core.coherenceIndex *= 0.9999f;
        core.coherenceIndex += 0.0001f;
    }
}

bool CosmicSingularityEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Singularity
