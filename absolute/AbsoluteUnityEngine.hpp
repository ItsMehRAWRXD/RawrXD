#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace AbsoluteUnity {

struct AbsoluteUnity {
    std::string id;
    std::string name;
    double absoluteness;   // Degree of absolute unity (0.0-1.0)
    double unity;          // Unity strength (0.0-1.0)
    double continuity;     // Continuity level (0.0-1.0)
    double omnipresence;   // Omnipresence factor (0.0-1.0)
    double harmony;        // Harmony level (0.0-1.0)
    double coherence;      // Coherence level (0.0-1.0)
    double clarity;        // Clarity level (0.0-1.0)
    double eternity;       // Eternity factor (0.0-1.0)
    double supremacy;      // Supremacy level (0.0-1.0)
    int64_t createdAt;
    int64_t lastUpdated;
    bool isActive;
    std::map<std::string, std::string> metadata;

    json ToJson() const;
    static AbsoluteUnity FromJson(const json& j);
};

struct UnityNode {
    std::string id;
    std::string absoluteId;
    double localUnity;         // Local unity value
    double globalUnity;        // Global unity value
    double resonanceFactor;    // Resonance contribution
    double coherenceLevel;     // Coherence level
    double clarityIndex;       // Clarity measurement
    double unityStrength;      // Unity strength
    double absolutenessLevel;  // Absoluteness level
    bool isUnified;
    bool isActive;
    int64_t createdAt;
    std::map<std::string, std::string> metadata;

    json ToJson() const;
    static UnityNode FromJson(const json& j);
    void AmplifyUnity(double amount);
    void UnifyNodes(UnityNode& other);
};

struct AbsoluteStream {
    std::string id;
    std::string name;
    double streamFlow;     // Flow rate of the stream
    double density;        // Stream density
    double clarity;        // Stream clarity
    double harmony;        // Stream harmony
    double continuity;     // Continuity level
    double omnipresence;   // Omnipresence factor
    double unity;          // Unity level
    double supremacy;      // Supremacy level
    double absoluteness;   // Absoluteness level
    bool isActive;
    int64_t createdAt;

    json ToJson() const;
    static AbsoluteStream FromJson(const json& j);
};

struct UnityWave {
    std::string id;
    std::string name;
    double amplitude;      // Wave amplitude
    double frequency;      // Wave frequency
    double clarity;        // Wave clarity
    double harmony;        // Wave harmony
    double omnipresence;   // Omnipresence factor
    double continuity;     // Continuity level
    double coherence;      // Coherence level
    double unity;          // Unity level
    double supremacy;      // Supremacy level
    double absoluteness;   // Absoluteness level
    bool isActive;
    int64_t createdAt;

    json ToJson() const;
    static UnityWave FromJson(const json& j);
};

struct AbsoluteMatrix {
    std::string id;
    std::string name;
    double matrix[13][13]; // 13x13 absolute matrix
    double coherence;      // Matrix coherence
    double clarity;        // Matrix clarity
    double harmony;        // Matrix harmony
    double continuity;     // Continuity level
    double omnipresence;   // Omnipresence factor
    double unity;          // Unity level
    double supremacy;      // Supremacy level
    double absoluteness;   // Absoluteness level
    double stability;      // Matrix stability
    int64_t createdAt;

    json ToJson() const;
    static AbsoluteMatrix FromJson(const json& j);
    void UnifyField();
};

struct AbsoluteTensor {
    std::string id;
    std::string name;
    double tensor[10][10][10]; // 10x10x10 absolute tensor
    double absoluteness;         // Absoluteness factor
    double clarity;              // Tensor clarity
    double harmony;              // Tensor harmony
    double omnipresence;         // Omnipresence factor
    double unity;                // Unity level
    double density;              // Tensor density
    double eternity;             // Eternity factor
    double supremacy;            // Supremacy factor
    int64_t createdAt;

    json ToJson() const;
    static AbsoluteTensor FromJson(const json& j);
};

struct AbsoluteClarity {
    std::string id;
    std::string name;
    double clarity;        // Clarity level
    double purity;         // Purity level
    double harmony;        // Harmony level
    double continuity;     // Continuity level
    double omnipresence;   // Omnipresence factor
    double coherence;      // Coherence level
    double unity;          // Unity level
    double density;        // Density level
    double supremacy;      // Supremacy level
    double absoluteness;   // Absoluteness level
    int64_t createdAt;

    json ToJson() const;
    static AbsoluteClarity FromJson(const json& j);
};

class AbsoluteUnityEngine {
public:
    static AbsoluteUnityEngine& GetInstance();
    
    void Initialize();
    void Shutdown();
    
    // AbsoluteUnity CRUD
    std::string CreateAbsoluteUnity(const std::string& name);
    std::shared_ptr<AbsoluteUnity> GetAbsoluteUnity(const std::string& id);
    std::vector<std::shared_ptr<AbsoluteUnity>> GetAllAbsoluteUnities();
    void UpdateAbsoluteUnity(const std::string& id, const AbsoluteUnity& unity);
    void DeleteAbsoluteUnity(const std::string& id);
    
    // UnityNode CRUD
    std::string CreateUnityNode(const std::string& absoluteId, const std::string& name);
    std::shared_ptr<UnityNode> GetUnityNode(const std::string& id);
    std::vector<std::shared_ptr<UnityNode>> GetUnityNodesForAbsolute(const std::string& absoluteId);
    std::vector<std::shared_ptr<UnityNode>> GetAllUnityNodes();
    void UpdateUnityNode(const std::string& id, const UnityNode& node);
    void DeleteUnityNode(const std::string& id);
    
    // AbsoluteStream CRUD
    std::string CreateAbsoluteStream(const std::string& name);
    std::shared_ptr<AbsoluteStream> GetAbsoluteStream(const std::string& id);
    std::vector<std::shared_ptr<AbsoluteStream>> GetAllAbsoluteStreams();
    void UpdateAbsoluteStream(const std::string& id, const AbsoluteStream& stream);
    void DeleteAbsoluteStream(const std::string& id);
    
    // UnityWave CRUD
    std::string CreateUnityWave(const std::string& name);
    std::shared_ptr<UnityWave> GetUnityWave(const std::string& id);
    std::vector<std::shared_ptr<UnityWave>> GetAllUnityWaves();
    void UpdateUnityWave(const std::string& id, const UnityWave& wave);
    void DeleteUnityWave(const std::string& id);
    
    // AbsoluteMatrix CRUD
    std::string CreateAbsoluteMatrix(const std::string& name);
    std::shared_ptr<AbsoluteMatrix> GetAbsoluteMatrix(const std::string& id);
    std::vector<std::shared_ptr<AbsoluteMatrix>> GetAllAbsoluteMatrices();
    void UpdateAbsoluteMatrix(const std::string& id, const AbsoluteMatrix& matrix);
    void DeleteAbsoluteMatrix(const std::string& id);
    
    // AbsoluteTensor CRUD
    std::string CreateAbsoluteTensor(const std::string& name);
    std::shared_ptr<AbsoluteTensor> GetAbsoluteTensor(const std::string& id);
    std::vector<std::shared_ptr<AbsoluteTensor>> GetAllAbsoluteTensors();
    void UpdateAbsoluteTensor(const std::string& id, const AbsoluteTensor& tensor);
    void DeleteAbsoluteTensor(const std::string& id);
    
    // AbsoluteClarity CRUD
    std::string CreateAbsoluteClarity(const std::string& name);
    std::shared_ptr<AbsoluteClarity> GetAbsoluteClarity(const std::string& id);
    std::vector<std::shared_ptr<AbsoluteClarity>> GetAllAbsoluteClarities();
    void UpdateAbsoluteClarity(const std::string& id, const AbsoluteClarity& clarity);
    void DeleteAbsoluteClarity(const std::string& id);
    
    // Operations
    void ExpandAbsolute(const std::string& absoluteId);
    void AmplifyUnity(const std::string& absoluteId);
    void StrengthenContinuity(const std::string& absoluteId);
    void ClarifyAbsolute(const std::string& absoluteId);
    void ElevateSupremacy(const std::string& absoluteId);
    void AchieveAbsoluteness(const std::string& absoluteId);
    
    // Serialization
    json SerializeAll() const;
    void DeserializeAll(const json& j);

private:
    AbsoluteUnityEngine() = default;
    ~AbsoluteUnityEngine() = default;
    
    std::string GenerateId() const;
    
    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<AbsoluteUnity>> absoluteUnities_;
    std::map<std::string, std::shared_ptr<UnityNode>> nodes_;
    std::map<std::string, std::shared_ptr<AbsoluteStream>> streams_;
    std::map<std::string, std::shared_ptr<UnityWave>> waves_;
    std::map<std::string, std::shared_ptr<AbsoluteMatrix>> matrices_;
    std::map<std::string, std::shared_ptr<AbsoluteTensor>> tensors_;
    std::map<std::string, std::shared_ptr<AbsoluteClarity>> clarities_;
};

} // namespace AbsoluteUnity
