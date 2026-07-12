#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <nlohmann/json.hpp>

namespace UniversalField {

using json = nlohmann::json;

// Forward declarations
struct UniversalField;
struct FieldNode;
struct UniversalStream;
struct FieldWave;
struct HarmonyMatrix;
struct UnityTensor;
struct UniversalClarity;

// UniversalField - Core universal field container
struct UniversalField {
    std::string id;
    std::string name;
    double universality;      // 0.0 to 1.0
    double permeation;        // 0.0 to 1.0
    double continuity;        // 0.0 to 1.0
    double omnipresence;      // 0.0 to 1.0
    double harmony;           // 0.0 to 1.0
    double coherence;         // 0.0 to 1.0
    double clarity;           // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastUpdated;
    bool isActive;
    std::map<std::string, std::string> metadata;

    UniversalField()
        : universality(0.0), permeation(0.0), continuity(0.0)
        , omnipresence(0.0), harmony(0.0), coherence(0.0), clarity(0.0)
        , createdAt(0), lastUpdated(0), isActive(false) {}

    json ToJson() const;
    static UniversalField FromJson(const json& j);
};

// FieldNode - Node within the universal field
struct FieldNode {
    std::string id;
    std::string fieldId;
    double localUniversality;
    double globalUniversality;
    double harmonyFactor;
    double coherenceLevel;
    double clarityIndex;
    double permeationStrength;
    bool isUnified;
    bool isActive;
    int64_t createdAt;
    std::map<std::string, std::string> metadata;

    FieldNode()
        : localUniversality(0.0), globalUniversality(0.0), harmonyFactor(0.0)
        , coherenceLevel(0.0), clarityIndex(0.0), permeationStrength(0.0)
        , isUnified(false), isActive(false), createdAt(0) {}

    json ToJson() const;
    static FieldNode FromJson(const json& j);

    void MergeUniversality(double otherUniversality);
    void UnifyNodes(FieldNode& other);
};

// UniversalStream - Flowing universality within the field
struct UniversalStream {
    std::string id;
    std::string name;
    double streamFlow;
    double density;
    double clarity;
    double harmony;
    double continuity;
    double omnipresence;
    double permeation;
    bool isActive;
    int64_t createdAt;

    UniversalStream()
        : streamFlow(0.0), density(0.0), clarity(0.0), harmony(0.0)
        , continuity(0.0), omnipresence(0.0), permeation(0.0)
        , isActive(false), createdAt(0) {}

    json ToJson() const;
    static UniversalStream FromJson(const json& j);
};

// FieldWave - Wave-based universality propagation
struct FieldWave {
    std::string id;
    std::string name;
    double amplitude;
    double frequency;
    double clarity;
    double harmony;
    double omnipresence;
    double continuity;
    double coherence;
    double permeation;
    bool isActive;
    int64_t createdAt;

    FieldWave()
        : amplitude(0.0), frequency(0.0), clarity(0.0), harmony(0.0)
        , omnipresence(0.0), continuity(0.0), coherence(0.0), permeation(0.0)
        , isActive(false), createdAt(0) {}

    json ToJson() const;
    static FieldWave FromJson(const json& j);
};

// HarmonyMatrix - 8x8 matrix for harmony harmonization
struct HarmonyMatrix {
    std::string id;
    std::string name;
    double matrix[8][8];      // 8x8 harmony matrix
    double coherence;
    double clarity;
    double harmony;
    double continuity;
    double omnipresence;
    double permeation;
    double stability;
    int64_t createdAt;

    HarmonyMatrix()
        : coherence(0.0), clarity(0.0), harmony(0.0), continuity(0.0)
        , omnipresence(0.0), permeation(0.0), stability(0.0), createdAt(0) {
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 8; ++j)
                matrix[i][j] = 0.0;
    }

    json ToJson() const;
    static HarmonyMatrix FromJson(const json& j);

    void StabilizeField();
};

// UnityTensor - 5x5x5 tensor for unity modeling
struct UnityTensor {
    std::string id;
    std::string name;
    double tensor[5][5][5];   // 5x5x5 unity tensor
    double unity;
    double clarity;
    double harmony;
    double omnipresence;
    double coherence;
    double permeation;
    double density;
    int64_t createdAt;

    UnityTensor()
        : unity(0.0), clarity(0.0), harmony(0.0), omnipresence(0.0)
        , coherence(0.0), permeation(0.0), density(0.0), createdAt(0) {
        for (int i = 0; i < 5; ++i)
            for (int j = 0; j < 5; ++j)
                for (int k = 0; k < 5; ++k)
                    tensor[i][j][k] = 0.0;
    }

    json ToJson() const;
    static UnityTensor FromJson(const json& j);
};

// UniversalClarity - Pure clarity manifestation
struct UniversalClarity {
    std::string id;
    std::string name;
    double clarity;
    double purity;
    double harmony;
    double continuity;
    double omnipresence;
    double coherence;
    double permeation;
    double density;
    int64_t createdAt;

    UniversalClarity()
        : clarity(0.0), purity(0.0), harmony(0.0), continuity(0.0)
        , omnipresence(0.0), coherence(0.0), permeation(0.0), density(0.0)
        , createdAt(0) {}

    json ToJson() const;
    static UniversalClarity FromJson(const json& j);
};

// Engine class
class UniversalFieldEngine {
public:
    static UniversalFieldEngine& GetInstance();

    // Initialize the engine
    void Initialize();
    void Shutdown();

    // Universal Field operations
    std::string CreateUniversalField(const std::string& name);
    std::shared_ptr<UniversalField> GetUniversalField(const std::string& id);
    std::vector<std::shared_ptr<UniversalField>> GetAllUniversalFields();
    void UpdateUniversalField(const std::string& id, const UniversalField& field);
    void DeleteUniversalField(const std::string& id);

    // Field Node operations
    std::string CreateFieldNode(const std::string& fieldId, const std::string& name);
    std::shared_ptr<FieldNode> GetFieldNode(const std::string& id);
    std::vector<std::shared_ptr<FieldNode>> GetFieldNodesForField(const std::string& fieldId);
    void UpdateFieldNode(const std::string& id, const FieldNode& node);
    void DeleteFieldNode(const std::string& id);

    // Universal Stream operations
    std::string CreateUniversalStream(const std::string& name);
    std::shared_ptr<UniversalStream> GetUniversalStream(const std::string& id);
    std::vector<std::shared_ptr<UniversalStream>> GetAllUniversalStreams();
    void UpdateUniversalStream(const std::string& id, const UniversalStream& stream);
    void DeleteUniversalStream(const std::string& id);

    // Field Wave operations
    std::string CreateFieldWave(const std::string& name);
    std::shared_ptr<FieldWave> GetFieldWave(const std::string& id);
    std::vector<std::shared_ptr<FieldWave>> GetAllFieldWaves();
    void UpdateFieldWave(const std::string& id, const FieldWave& wave);
    void DeleteFieldWave(const std::string& id);

    // Harmony Matrix operations
    std::string CreateHarmonyMatrix(const std::string& name);
    std::shared_ptr<HarmonyMatrix> GetHarmonyMatrix(const std::string& id);
    std::vector<std::shared_ptr<HarmonyMatrix>> GetAllHarmonyMatrices();
    void UpdateHarmonyMatrix(const std::string& id, const HarmonyMatrix& matrix);
    void DeleteHarmonyMatrix(const std::string& id);

    // Unity Tensor operations
    std::string CreateUnityTensor(const std::string& name);
    std::shared_ptr<UnityTensor> GetUnityTensor(const std::string& id);
    std::vector<std::shared_ptr<UnityTensor>> GetAllUnityTensors();
    void UpdateUnityTensor(const std::string& id, const UnityTensor& tensor);
    void DeleteUnityTensor(const std::string& id);

    // Universal Clarity operations
    std::string CreateUniversalClarity(const std::string& name);
    std::shared_ptr<UniversalClarity> GetUniversalClarity(const std::string& id);
    std::vector<std::shared_ptr<UniversalClarity>> GetAllUniversalClarities();
    void UpdateUniversalClarity(const std::string& id, const UniversalClarity& clarity);
    void DeleteUniversalClarity(const std::string& id);

    // Actions
    void ExpandField(const std::string& fieldId);
    void AmplifyHarmony(const std::string& fieldId);
    void StrengthenContinuity(const std::string& fieldId);
    void ClarifyUniversality(const std::string& fieldId);

    // Serialization
    json SerializeAll() const;
    void DeserializeAll(const json& j);

private:
    UniversalFieldEngine() = default;
    ~UniversalFieldEngine() = default;
    UniversalFieldEngine(const UniversalFieldEngine&) = delete;
    UniversalFieldEngine& operator=(const UniversalFieldEngine&) = delete;

    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<UniversalField>> fields_;
    std::map<std::string, std::shared_ptr<FieldNode>> nodes_;
    std::map<std::string, std::shared_ptr<UniversalStream>> streams_;
    std::map<std::string, std::shared_ptr<FieldWave>> waves_;
    std::map<std::string, std::shared_ptr<HarmonyMatrix>> matrices_;
    std::map<std::string, std::shared_ptr<UnityTensor>> tensors_;
    std::map<std::string, std::shared_ptr<UniversalClarity>> clarities_;

    std::string GenerateId() const;
};

} // namespace UniversalField
