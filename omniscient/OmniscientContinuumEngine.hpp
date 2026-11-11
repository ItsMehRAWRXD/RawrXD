#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <map>
#include <array>
#include <nlohmann/json.hpp>

namespace OmniscientContinuum {

// Forward declarations
struct OmniscientField;
struct ContinuumNode;
struct AwarenessStream;
struct PerceptionWave;
struct ResonanceMatrix;
struct ContinuityTensor;
struct OmniscientClarity;

using json = nlohmann::json;

// Core data structures

struct OmniscientField {
    std::string id;
    std::string name;
    std::string description;
    
    // Omniscient field properties
    float awareness;
    float perception;
    float continuity;
    float omnipresence;
    float resonance;
    float coherence;
    float clarity;
    
    // Metadata
    std::string createdAt;
    std::string modifiedAt;
    bool isActive;
    
    OmniscientField() : awareness(0.0f), perception(0.0f), continuity(0.0f), 
                        omnipresence(0.0f), resonance(0.0f), coherence(0.0f), 
                        clarity(0.0f), isActive(true) {}
    
    json ToJson() const;
    static OmniscientField FromJson(const json& j);
};

struct ContinuumNode {
    std::string id;
    std::string name;
    std::string parentId;
    
    float localAwareness;
    float globalAwareness;
    float resonanceFactor;
    float coherenceLevel;
    float clarityIndex;
    float continuityStrength;
    bool isUnified;
    
    std::string unifiedAt;
    
    ContinuumNode() : localAwareness(0.0f), globalAwareness(0.0f), resonanceFactor(0.0f), 
                      coherenceLevel(0.0f), clarityIndex(0.0f), continuityStrength(0.0f), 
                      isUnified(false) {}
    
    json ToJson() const;
    static ContinuumNode FromJson(const json& j);
};

struct AwarenessStream {
    std::string id;
    std::string name;
    std::string parentId;
    
    float streamFlow;
    float density;
    float clarity;
    float resonance;
    float continuity;
    float omnipresence;
    bool isActive;
    
    AwarenessStream() : streamFlow(0.0f), density(0.0f), clarity(0.0f), 
                        resonance(0.0f), continuity(0.0f), omnipresence(0.0f), 
                        isActive(false) {}
    
    json ToJson() const;
    static AwarenessStream FromJson(const json& j);
};

struct PerceptionWave {
    std::string id;
    std::string name;
    std::string parentId;
    
    float amplitude;
    float frequency;
    float clarity;
    float resonance;
    float omnipresence;
    float continuity;
    float coherence;
    
    PerceptionWave() : amplitude(0.0f), frequency(0.0f), clarity(0.0f), 
                       resonance(0.0f), omnipresence(0.0f), continuity(0.0f), 
                       coherence(0.0f) {}
    
    json ToJson() const;
    static PerceptionWave FromJson(const json& j);
};

struct ResonanceMatrix {
    std::string id;
    std::string name;
    std::string parentId;
    
    std::array<std::array<float, 7>, 7> matrix;
    float coherence;
    float clarity;
    float resonance;
    float continuity;
    float omnipresence;
    float stability;
    
    ResonanceMatrix() : coherence(0.0f), clarity(0.0f), resonance(0.0f), 
                      continuity(0.0f), omnipresence(0.0f), stability(0.0f) {
        for (auto& row : matrix) {
            row.fill(0.0f);
        }
    }
    
    json ToJson() const;
    static ResonanceMatrix FromJson(const json& j);
};

struct ContinuityTensor {
    std::string id;
    std::string name;
    std::string parentId;
    
    std::array<std::array<std::array<float, 4>, 4>, 4> tensor;
    float continuity;
    float clarity;
    float resonance;
    float omnipresence;
    float coherence;
    float density;
    
    ContinuityTensor() : continuity(0.0f), clarity(0.0f), resonance(0.0f), 
                       omnipresence(0.0f), coherence(0.0f), density(0.0f) {
        for (auto& plane : tensor) {
            for (auto& row : plane) {
                row.fill(0.0f);
            }
        }
    }
    
    json ToJson() const;
    static ContinuityTensor FromJson(const json& j);
};

struct OmniscientClarity {
    std::string id;
    std::string name;
    std::string parentId;
    
    float clarity;
    float purity;
    float resonance;
    float continuity;
    float omnipresence;
    float coherence;
    float density;
    
    OmniscientClarity() : clarity(0.0f), purity(0.0f), resonance(0.0f), 
                          continuity(0.0f), omnipresence(0.0f), coherence(0.0f), 
                          density(0.0f) {}
    
    json ToJson() const;
    static OmniscientClarity FromJson(const json& j);
};

// Main engine class
class OmniscientContinuumEngine {
public:
    // Initialization
    static bool Initialize();
    static void Shutdown();
    static bool IsInitialized();
    
    // Omniscient field operations
    static std::string CreateOmniscientField(const std::string& name);
    static std::shared_ptr<OmniscientField> GetOmniscientField(const std::string& id);
    static bool UpdateOmniscientField(const std::string& id, const OmniscientField& field);
    static bool DeleteOmniscientField(const std::string& id);
    static std::vector<std::string> GetAllOmniscientFieldIds();
    static std::vector<std::shared_ptr<OmniscientField>> GetAllOmniscientFields();
    
    // Continuum node operations
    static std::string CreateContinuumNode(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<ContinuumNode> GetContinuumNode(const std::string& id);
    static bool UpdateContinuumNode(const std::string& id, const ContinuumNode& node);
    static bool DeleteContinuumNode(const std::string& id);
    static std::vector<std::string> GetAllContinuumNodeIds();
    static std::vector<std::shared_ptr<ContinuumNode>> GetAllContinuumNodes();
    
    // Awareness stream operations
    static std::string CreateAwarenessStream(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<AwarenessStream> GetAwarenessStream(const std::string& id);
    static bool UpdateAwarenessStream(const std::string& id, const AwarenessStream& stream);
    static bool DeleteAwarenessStream(const std::string& id);
    static std::vector<std::string> GetAllAwarenessStreamIds();
    static std::vector<std::shared_ptr<AwarenessStream>> GetAllAwarenessStreams();
    
    // Perception wave operations
    static std::string CreatePerceptionWave(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<PerceptionWave> GetPerceptionWave(const std::string& id);
    static bool UpdatePerceptionWave(const std::string& id, const PerceptionWave& wave);
    static bool DeletePerceptionWave(const std::string& id);
    static std::vector<std::string> GetAllPerceptionWaveIds();
    static std::vector<std::shared_ptr<PerceptionWave>> GetAllPerceptionWaves();
    
    // Resonance matrix operations
    static std::string CreateResonanceMatrix(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<ResonanceMatrix> GetResonanceMatrix(const std::string& id);
    static bool UpdateResonanceMatrix(const std::string& id, const ResonanceMatrix& matrix);
    static bool DeleteResonanceMatrix(const std::string& id);
    static std::vector<std::string> GetAllResonanceMatrixIds();
    static std::vector<std::shared_ptr<ResonanceMatrix>> GetAllResonanceMatrices();
    
    // Continuity tensor operations
    static std::string CreateContinuityTensor(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<ContinuityTensor> GetContinuityTensor(const std::string& id);
    static bool UpdateContinuityTensor(const std::string& id, const ContinuityTensor& tensor);
    static bool DeleteContinuityTensor(const std::string& id);
    static std::vector<std::string> GetAllContinuityTensorIds();
    static std::vector<std::shared_ptr<ContinuityTensor>> GetAllContinuityTensors();
    
    // Omniscient clarity operations
    static std::string CreateOmniscientClarity(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<OmniscientClarity> GetOmniscientClarity(const std::string& id);
    static bool UpdateOmniscientClarity(const std::string& id, const OmniscientClarity& clarity);
    static bool DeleteOmniscientClarity(const std::string& id);
    static std::vector<std::string> GetAllOmniscientClarityIds();
    static std::vector<std::shared_ptr<OmniscientClarity>> GetAllOmniscientClarities();
    
    // Action operations
    static bool ExpandContinuum(const std::string& id);
    static bool MergeAwareness(const std::string& id);
    static bool AmplifyResonance(const std::string& id);
    static bool StrengthenContinuity(const std::string& id);
    static bool ClarifyOmniscience(const std::string& id);
    static bool StabilizeField(const std::string& id);
    static bool UnifyNodes(const std::string& id);
    
    // Utility
    static void ClearAll();
    static size_t GetTotalStructureCount();
    
private:
    static std::atomic<bool> s_initialized;
    
    static std::mutex s_fieldMutex;
    static std::mutex s_nodeMutex;
    static std::mutex s_streamMutex;
    static std::mutex s_waveMutex;
    static std::mutex s_matrixMutex;
    static std::mutex s_tensorMutex;
    static std::mutex s_clarityMutex;
    
    static std::map<std::string, std::shared_ptr<OmniscientField>> s_fields;
    static std::map<std::string, std::shared_ptr<ContinuumNode>> s_nodes;
    static std::map<std::string, std::shared_ptr<AwarenessStream>> s_streams;
    static std::map<std::string, std::shared_ptr<PerceptionWave>> s_waves;
    static std::map<std::string, std::shared_ptr<ResonanceMatrix>> s_matrices;
    static std::map<std::string, std::shared_ptr<ContinuityTensor>> s_tensors;
    static std::map<std::string, std::shared_ptr<OmniscientClarity>> s_clarities;
    
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace OmniscientContinuum
