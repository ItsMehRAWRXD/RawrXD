#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <nlohmann/json.hpp>

namespace CosmicUnity {

using json = nlohmann::json;

// Forward declarations
struct CosmicUnity;
struct UnityNode;
struct CosmicStream;
struct UnityWave;
struct SynthesisMatrix;
struct CoherenceTensor;
struct CosmicClarity;

// CosmicUnity - Core cosmic unity container
struct CosmicUnity {
    std::string id;
    std::string name;
    double unity;             // 0.0 to 1.0
    double synthesis;         // 0.0 to 1.0
    double continuity;        // 0.0 to 1.0
    double omnipresence;      // 0.0 to 1.0
    double harmony;           // 0.0 to 1.0
    double coherence;         // 0.0 to 1.0
    double clarity;           // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastUpdated;
    bool isActive;
    std::map<std::string, std::string> metadata;

    CosmicUnity()
        : unity(0.0), synthesis(0.0), continuity(0.0)
        , omnipresence(0.0), harmony(0.0), coherence(0.0), clarity(0.0)
        , createdAt(0), lastUpdated(0), isActive(false) {}

    json ToJson() const;
    static CosmicUnity FromJson(const json& j);
};

// UnityNode - Node within the cosmic unity
struct UnityNode {
    std::string id;
    std::string cosmicId;
    double localUnity;
    double globalUnity;
    double harmonyFactor;
    double coherenceLevel;
    double clarityIndex;
    double synthesisStrength;
    bool isUnified;
    bool isActive;
    int64_t createdAt;
    std::map<std::string, std::string> metadata;

    UnityNode()
        : localUnity(0.0), globalUnity(0.0), harmonyFactor(0.0)
        , coherenceLevel(0.0), clarityIndex(0.0), synthesisStrength(0.0)
        , isUnified(false), isActive(false), createdAt(0) {}

    json ToJson() const;
    static UnityNode FromJson(const json& j);

    void MergeUnity(double otherUnity);
    void UnifyNodes(UnityNode& other);
};

// CosmicStream - Flowing unity within the cosmic
struct CosmicStream {
    std::string id;
    std::string name;
    double streamFlow;
    double density;
    double clarity;
    double harmony;
    double continuity;
    double omnipresence;
    double synthesis;
    bool isActive;
    int64_t createdAt;

    CosmicStream()
        : streamFlow(0.0), density(0.0), clarity(0.0), harmony(0.0)
        , continuity(0.0), omnipresence(0.0), synthesis(0.0)
        , isActive(false), createdAt(0) {}

    json ToJson() const;
    static CosmicStream FromJson(const json& j);
};

// UnityWave - Wave-based unity propagation
struct UnityWave {
    std::string id;
    std::string name;
    double amplitude;
    double frequency;
    double clarity;
    double harmony;
    double omnipresence;
    double continuity;
    double coherence;
    double synthesis;
    bool isActive;
    int64_t createdAt;

    UnityWave()
        : amplitude(0.0), frequency(0.0), clarity(0.0), harmony(0.0)
        , omnipresence(0.0), continuity(0.0), coherence(0.0), synthesis(0.0)
        , isActive(false), createdAt(0) {}

    json ToJson() const;
    static UnityWave FromJson(const json& j);
};

// SynthesisMatrix - 9x9 matrix for synthesis harmonization
struct SynthesisMatrix {
    std::string id;
    std::string name;
    double matrix[9][9];      // 9x9 synthesis matrix
    double coherence;
    double clarity;
    double harmony;
    double continuity;
    double omnipresence;
    double synthesis;
    double stability;
    int64_t createdAt;

    SynthesisMatrix()
        : coherence(0.0), clarity(0.0), harmony(0.0), continuity(0.0)
        , omnipresence(0.0), synthesis(0.0), stability(0.0), createdAt(0) {
        for (int i = 0; i < 9; ++i)
            for (int j = 0; j < 9; ++j)
                matrix[i][j] = 0.0;
    }

    json ToJson() const;
    static SynthesisMatrix FromJson(const json& j);

    void StabilizeField();
};

// CoherenceTensor - 6x6x6 tensor for coherence modeling
struct CoherenceTensor {
    std::string id;
    std::string name;
    double tensor[6][6][6];   // 6x6x6 coherence tensor
    double coherence;
    double clarity;
    double harmony;
    double omnipresence;
    double synthesis;
    double density;
    int64_t createdAt;

    CoherenceTensor()
        : coherence(0.0), clarity(0.0), harmony(0.0), omnipresence(0.0)
        , synthesis(0.0), density(0.0), createdAt(0) {
        for (int i = 0; i < 6; ++i)
            for (int j = 0; j < 6; ++j)
                for (int k = 0; k < 6; ++k)
                    tensor[i][j][k] = 0.0;
    }

    json ToJson() const;
    static CoherenceTensor FromJson(const json& j);
};

// CosmicClarity - Pure clarity manifestation
struct CosmicClarity {
    std::string id;
    std::string name;
    double clarity;
    double purity;
    double harmony;
    double continuity;
    double omnipresence;
    double coherence;
    double synthesis;
    double density;
    int64_t createdAt;

    CosmicClarity()
        : clarity(0.0), purity(0.0), harmony(0.0), continuity(0.0)
        , omnipresence(0.0), coherence(0.0), synthesis(0.0), density(0.0)
        , createdAt(0) {}

    json ToJson() const;
    static CosmicClarity FromJson(const json& j);
};

// Engine class
class CosmicUnityEngine {
public:
    static CosmicUnityEngine& GetInstance();

    // Initialize the engine
    void Initialize();
    void Shutdown();

    // Cosmic Unity operations
    std::string CreateCosmicUnity(const std::string& name);
    std::shared_ptr<CosmicUnity> GetCosmicUnity(const std::string& id);
    std::vector<std::shared_ptr<CosmicUnity>> GetAllCosmicUnities();
    void UpdateCosmicUnity(const std::string& id, const CosmicUnity& cosmic);
    void DeleteCosmicUnity(const std::string& id);

    // Unity Node operations
    std::string CreateUnityNode(const std::string& cosmicId, const std::string& name);
    std::shared_ptr<UnityNode> GetUnityNode(const std::string& id);
    std::vector<std::shared_ptr<UnityNode>> GetUnityNodesForCosmic(const std::string& cosmicId);
    void UpdateUnityNode(const std::string& id, const UnityNode& node);
    void DeleteUnityNode(const std::string& id);

    // Cosmic Stream operations
    std::string CreateCosmicStream(const std::string& name);
    std::shared_ptr<CosmicStream> GetCosmicStream(const std::string& id);
    std::vector<std::shared_ptr<CosmicStream>> GetAllCosmicStreams();
    void UpdateCosmicStream(const std::string& id, const CosmicStream& stream);
    void DeleteCosmicStream(const std::string& id);

    // Unity Wave operations
    std::string CreateUnityWave(const std::string& name);
    std::shared_ptr<UnityWave> GetUnityWave(const std::string& id);
    std::vector<std::shared_ptr<UnityWave>> GetAllUnityWaves();
    void UpdateUnityWave(const std::string& id, const UnityWave& wave);
    void DeleteUnityWave(const std::string& id);

    // Synthesis Matrix operations
    std::string CreateSynthesisMatrix(const std::string& name);
    std::shared_ptr<SynthesisMatrix> GetSynthesisMatrix(const std::string& id);
    std::vector<std::shared_ptr<SynthesisMatrix>> GetAllSynthesisMatrices();
    void UpdateSynthesisMatrix(const std::string& id, const SynthesisMatrix& matrix);
    void DeleteSynthesisMatrix(const std::string& id);

    // Coherence Tensor operations
    std::string CreateCoherenceTensor(const std::string& name);
    std::shared_ptr<CoherenceTensor> GetCoherenceTensor(const std::string& id);
    std::vector<std::shared_ptr<CoherenceTensor>> GetAllCoherenceTensors();
    void UpdateCoherenceTensor(const std::string& id, const CoherenceTensor& tensor);
    void DeleteCoherenceTensor(const std::string& id);

    // Cosmic Clarity operations
    std::string CreateCosmicClarity(const std::string& name);
    std::shared_ptr<CosmicClarity> GetCosmicClarity(const std::string& id);
    std::vector<std::shared_ptr<CosmicClarity>> GetAllCosmicClarities();
    void UpdateCosmicClarity(const std::string& id, const CosmicClarity& clarity);
    void DeleteCosmicClarity(const std::string& id);

    // Actions
    void ExpandCosmic(const std::string& cosmicId);
    void AmplifyHarmony(const std::string& cosmicId);
    void StrengthenContinuity(const std::string& cosmicId);
    void ClarifyCosmic(const std::string& cosmicId);

    // Serialization
    json SerializeAll() const;
    void DeserializeAll(const json& j);

private:
    CosmicUnityEngine() = default;
    ~CosmicUnityEngine() = default;
    CosmicUnityEngine(const CosmicUnityEngine&) = delete;
    CosmicUnityEngine& operator=(const CosmicUnityEngine&) = delete;

    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<CosmicUnity>> cosmicUnities_;
    std::map<std::string, std::shared_ptr<UnityNode>> nodes_;
    std::map<std::string, std::shared_ptr<CosmicStream>> streams_;
    std::map<std::string, std::shared_ptr<UnityWave>> waves_;
    std::map<std::string, std::shared_ptr<SynthesisMatrix>> matrices_;
    std::map<std::string, std::shared_ptr<CoherenceTensor>> tensors_;
    std::map<std::string, std::shared_ptr<CosmicClarity>> clarities_;

    std::string GenerateId() const;
};

} // namespace CosmicUnity
