#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace SupremeHarmony {

struct SupremeHarmony {
    std::string id;
    std::string name;
    double supremacy;      // Degree of supreme harmony (0.0-1.0)
    double unity;          // Unity strength (0.0-1.0)
    double continuity;     // Continuity level (0.0-1.0)
    double omnipresence;   // Omnipresence factor (0.0-1.0)
    double harmony;        // Harmony level (0.0-1.0)
    double coherence;      // Coherence level (0.0-1.0)
    double clarity;        // Clarity level (0.0-1.0)
    double eternity;       // Eternity factor (0.0-1.0)
    int64_t createdAt;
    int64_t lastUpdated;
    bool isActive;
    std::map<std::string, std::string> metadata;

    json ToJson() const;
    static SupremeHarmony FromJson(const json& j);
};

struct HarmonyNode {
    std::string id;
    std::string supremeId;
    double localHarmony;       // Local harmony value
    double globalHarmony;      // Global harmony value
    double resonanceFactor;    // Resonance contribution
    double coherenceLevel;     // Coherence level
    double clarityIndex;       // Clarity measurement
    double unityStrength;      // Unity strength
    double supremacyLevel;     // Supremacy level
    bool isUnified;
    bool isActive;
    int64_t createdAt;
    std::map<std::string, std::string> metadata;

    json ToJson() const;
    static HarmonyNode FromJson(const json& j);
    void AmplifyHarmony(double amount);
    void UnifyNodes(HarmonyNode& other);
};

struct SupremeStream {
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
    bool isActive;
    int64_t createdAt;

    json ToJson() const;
    static SupremeStream FromJson(const json& j);
};

struct HarmonyWave {
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
    bool isActive;
    int64_t createdAt;

    json ToJson() const;
    static HarmonyWave FromJson(const json& j);
};

struct SupremeMatrix {
    std::string id;
    std::string name;
    double matrix[12][12]; // 12x12 supreme matrix
    double coherence;      // Matrix coherence
    double clarity;        // Matrix clarity
    double harmony;        // Matrix harmony
    double continuity;     // Continuity level
    double omnipresence;   // Omnipresence factor
    double unity;          // Unity level
    double supremacy;      // Supremacy level
    double stability;      // Matrix stability
    int64_t createdAt;

    json ToJson() const;
    static SupremeMatrix FromJson(const json& j);
    void HarmonizeField();
};

struct SupremeTensor {
    std::string id;
    std::string name;
    double tensor[9][9][9]; // 9x9x9 supreme tensor
    double supremacy;        // Supremacy factor
    double clarity;         // Tensor clarity
    double harmony;         // Tensor harmony
    double omnipresence;    // Omnipresence factor
    double unity;           // Unity level
    double density;         // Tensor density
    double eternity;        // Eternity factor
    int64_t createdAt;

    json ToJson() const;
    static SupremeTensor FromJson(const json& j);
};

struct SupremeClarity {
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
    int64_t createdAt;

    json ToJson() const;
    static SupremeClarity FromJson(const json& j);
};

class SupremeHarmonyEngine {
public:
    static SupremeHarmonyEngine& GetInstance();
    
    void Initialize();
    void Shutdown();
    
    // SupremeHarmony CRUD
    std::string CreateSupremeHarmony(const std::string& name);
    std::shared_ptr<SupremeHarmony> GetSupremeHarmony(const std::string& id);
    std::vector<std::shared_ptr<SupremeHarmony>> GetAllSupremeHarmonies();
    void UpdateSupremeHarmony(const std::string& id, const SupremeHarmony& harmony);
    void DeleteSupremeHarmony(const std::string& id);
    
    // HarmonyNode CRUD
    std::string CreateHarmonyNode(const std::string& supremeId, const std::string& name);
    std::shared_ptr<HarmonyNode> GetHarmonyNode(const std::string& id);
    std::vector<std::shared_ptr<HarmonyNode>> GetHarmonyNodesForSupreme(const std::string& supremeId);
    std::vector<std::shared_ptr<HarmonyNode>> GetAllHarmonyNodes();
    void UpdateHarmonyNode(const std::string& id, const HarmonyNode& node);
    void DeleteHarmonyNode(const std::string& id);
    
    // SupremeStream CRUD
    std::string CreateSupremeStream(const std::string& name);
    std::shared_ptr<SupremeStream> GetSupremeStream(const std::string& id);
    std::vector<std::shared_ptr<SupremeStream>> GetAllSupremeStreams();
    void UpdateSupremeStream(const std::string& id, const SupremeStream& stream);
    void DeleteSupremeStream(const std::string& id);
    
    // HarmonyWave CRUD
    std::string CreateHarmonyWave(const std::string& name);
    std::shared_ptr<HarmonyWave> GetHarmonyWave(const std::string& id);
    std::vector<std::shared_ptr<HarmonyWave>> GetAllHarmonyWaves();
    void UpdateHarmonyWave(const std::string& id, const HarmonyWave& wave);
    void DeleteHarmonyWave(const std::string& id);
    
    // SupremeMatrix CRUD
    std::string CreateSupremeMatrix(const std::string& name);
    std::shared_ptr<SupremeMatrix> GetSupremeMatrix(const std::string& id);
    std::vector<std::shared_ptr<SupremeMatrix>> GetAllSupremeMatrices();
    void UpdateSupremeMatrix(const std::string& id, const SupremeMatrix& matrix);
    void DeleteSupremeMatrix(const std::string& id);
    
    // SupremeTensor CRUD
    std::string CreateSupremeTensor(const std::string& name);
    std::shared_ptr<SupremeTensor> GetSupremeTensor(const std::string& id);
    std::vector<std::shared_ptr<SupremeTensor>> GetAllSupremeTensors();
    void UpdateSupremeTensor(const std::string& id, const SupremeTensor& tensor);
    void DeleteSupremeTensor(const std::string& id);
    
    // SupremeClarity CRUD
    std::string CreateSupremeClarity(const std::string& name);
    std::shared_ptr<SupremeClarity> GetSupremeClarity(const std::string& id);
    std::vector<std::shared_ptr<SupremeClarity>> GetAllSupremeClarities();
    void UpdateSupremeClarity(const std::string& id, const SupremeClarity& clarity);
    void DeleteSupremeClarity(const std::string& id);
    
    // Operations
    void ExpandSupreme(const std::string& supremeId);
    void AmplifyHarmony(const std::string& supremeId);
    void StrengthenContinuity(const std::string& supremeId);
    void ClarifySupreme(const std::string& supremeId);
    void ElevateSupremacy(const std::string& supremeId);
    
    // Serialization
    json SerializeAll() const;
    void DeserializeAll(const json& j);

private:
    SupremeHarmonyEngine() = default;
    ~SupremeHarmonyEngine() = default;
    
    std::string GenerateId() const;
    
    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<SupremeHarmony>> supremeHarmonies_;
    std::map<std::string, std::shared_ptr<HarmonyNode>> nodes_;
    std::map<std::string, std::shared_ptr<SupremeStream>> streams_;
    std::map<std::string, std::shared_ptr<HarmonyWave>> waves_;
    std::map<std::string, std::shared_ptr<SupremeMatrix>> matrices_;
    std::map<std::string, std::shared_ptr<SupremeTensor>> tensors_;
    std::map<std::string, std::shared_ptr<SupremeClarity>> clarities_;
};

} // namespace SupremeHarmony
