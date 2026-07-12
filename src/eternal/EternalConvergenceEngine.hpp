#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <nlohmann/json.hpp>

namespace EternalConvergence {

using json = nlohmann::json;

struct EternalConvergence;
struct ConvergenceNode;
struct EternalStream;
struct ConvergenceWave;
struct UnityMatrix;
struct EternalTensor;
struct EternalClarity;

struct EternalConvergence {
    std::string id;
    std::string name;
    double convergence;
    double unity;
    double continuity;
    double omnipresence;
    double harmony;
    double coherence;
    double clarity;
    int64_t createdAt;
    int64_t lastUpdated;
    bool isActive;
    std::map<std::string, std::string> metadata;

    EternalConvergence()
        : convergence(0.0), unity(0.0), continuity(0.0)
        , omnipresence(0.0), harmony(0.0), coherence(0.0), clarity(0.0)
        , createdAt(0), lastUpdated(0), isActive(false) {}

    json ToJson() const;
    static EternalConvergence FromJson(const json& j);
};

struct ConvergenceNode {
    std::string id;
    std::string eternalId;
    double localConvergence;
    double globalConvergence;
    double harmonyFactor;
    double coherenceLevel;
    double clarityIndex;
    double unityStrength;
    bool isUnified;
    bool isActive;
    int64_t createdAt;
    std::map<std::string, std::string> metadata;

    ConvergenceNode()
        : localConvergence(0.0), globalConvergence(0.0), harmonyFactor(0.0)
        , coherenceLevel(0.0), clarityIndex(0.0), unityStrength(0.0)
        , isUnified(false), isActive(false), createdAt(0) {}

    json ToJson() const;
    static ConvergenceNode FromJson(const json& j);

    void MergeConvergence(double otherConvergence);
    void UnifyNodes(ConvergenceNode& other);
};

struct EternalStream {
    std::string id;
    std::string name;
    double streamFlow;
    double density;
    double clarity;
    double harmony;
    double continuity;
    double omnipresence;
    double unity;
    bool isActive;
    int64_t createdAt;

    EternalStream()
        : streamFlow(0.0), density(0.0), clarity(0.0), harmony(0.0)
        , continuity(0.0), omnipresence(0.0), unity(0.0)
        , isActive(false), createdAt(0) {}

    json ToJson() const;
    static EternalStream FromJson(const json& j);
};

struct ConvergenceWave {
    std::string id;
    std::string name;
    double amplitude;
    double frequency;
    double clarity;
    double harmony;
    double omnipresence;
    double continuity;
    double coherence;
    double unity;
    bool isActive;
    int64_t createdAt;

    ConvergenceWave()
        : amplitude(0.0), frequency(0.0), clarity(0.0), harmony(0.0)
        , omnipresence(0.0), continuity(0.0), coherence(0.0), unity(0.0)
        , isActive(false), createdAt(0) {}

    json ToJson() const;
    static ConvergenceWave FromJson(const json& j);
};

struct UnityMatrix {
    std::string id;
    std::string name;
    double matrix[11][11];
    double coherence;
    double clarity;
    double harmony;
    double continuity;
    double omnipresence;
    double unity;
    double stability;
    int64_t createdAt;

    UnityMatrix()
        : coherence(0.0), clarity(0.0), harmony(0.0), continuity(0.0)
        , omnipresence(0.0), unity(0.0), stability(0.0), createdAt(0) {
        for (int i = 0; i < 11; ++i)
            for (int j = 0; j < 11; ++j)
                matrix[i][j] = 0.0;
    }

    json ToJson() const;
    static UnityMatrix FromJson(const json& j);

    void StabilizeField();
};

struct EternalTensor {
    std::string id;
    std::string name;
    double tensor[8][8][8];
    double eternity;
    double clarity;
    double harmony;
    double omnipresence;
    double unity;
    double density;
    int64_t createdAt;

    EternalTensor()
        : eternity(0.0), clarity(0.0), harmony(0.0), omnipresence(0.0)
        , unity(0.0), density(0.0), createdAt(0) {
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 8; ++j)
                for (int k = 0; k < 8; ++k)
                    tensor[i][j][k] = 0.0;
    }

    json ToJson() const;
    static EternalTensor FromJson(const json& j);
};

struct EternalClarity {
    std::string id;
    std::string name;
    double clarity;
    double purity;
    double harmony;
    double continuity;
    double omnipresence;
    double coherence;
    double unity;
    double density;
    int64_t createdAt;

    EternalClarity()
        : clarity(0.0), purity(0.0), harmony(0.0), continuity(0.0)
        , omnipresence(0.0), coherence(0.0), unity(0.0), density(0.0)
        , createdAt(0) {}

    json ToJson() const;
    static EternalClarity FromJson(const json& j);
};

class EternalConvergenceEngine {
public:
    static EternalConvergenceEngine& GetInstance();

    void Initialize();
    void Shutdown();

    std::string CreateEternalConvergence(const std::string& name);
    std::shared_ptr<EternalConvergence> GetEternalConvergence(const std::string& id);
    std::vector<std::shared_ptr<EternalConvergence>> GetAllEternalConvergences();
    void UpdateEternalConvergence(const std::string& id, const EternalConvergence& eternal);
    void DeleteEternalConvergence(const std::string& id);

    std::string CreateConvergenceNode(const std::string& eternalId, const std::string& name);
    std::shared_ptr<ConvergenceNode> GetConvergenceNode(const std::string& id);
    std::vector<std::shared_ptr<ConvergenceNode>> GetConvergenceNodesForEternal(const std::string& eternalId);
    void UpdateConvergenceNode(const std::string& id, const ConvergenceNode& node);
    void DeleteConvergenceNode(const std::string& id);

    std::string CreateEternalStream(const std::string& name);
    std::shared_ptr<EternalStream> GetEternalStream(const std::string& id);
    std::vector<std::shared_ptr<EternalStream>> GetAllEternalStreams();
    void UpdateEternalStream(const std::string& id, const EternalStream& stream);
    void DeleteEternalStream(const std::string& id);

    std::string CreateConvergenceWave(const std::string& name);
    std::shared_ptr<ConvergenceWave> GetConvergenceWave(const std::string& id);
    std::vector<std::shared_ptr<ConvergenceWave>> GetAllConvergenceWaves();
    void UpdateConvergenceWave(const std::string& id, const ConvergenceWave& wave);
    void DeleteConvergenceWave(const std::string& id);

    std::string CreateUnityMatrix(const std::string& name);
    std::shared_ptr<UnityMatrix> GetUnityMatrix(const std::string& id);
    std::vector<std::shared_ptr<UnityMatrix>> GetAllUnityMatrices();
    void UpdateUnityMatrix(const std::string& id, const UnityMatrix& matrix);
    void DeleteUnityMatrix(const std::string& id);

    std::string CreateEternalTensor(const std::string& name);
    std::shared_ptr<EternalTensor> GetEternalTensor(const std::string& id);
    std::vector<std::shared_ptr<EternalTensor>> GetAllEternalTensors();
    void UpdateEternalTensor(const std::string& id, const EternalTensor& tensor);
    void DeleteEternalTensor(const std::string& id);

    std::string CreateEternalClarity(const std::string& name);
    std::shared_ptr<EternalClarity> GetEternalClarity(const std::string& id);
    std::vector<std::shared_ptr<EternalClarity>> GetAllEternalClarities();
    void UpdateEternalClarity(const std::string& id, const EternalClarity& clarity);
    void DeleteEternalClarity(const std::string& id);

    void ExpandEternal(const std::string& eternalId);
    void AmplifyHarmony(const std::string& eternalId);
    void StrengthenContinuity(const std::string& eternalId);
    void ClarifyEternal(const std::string& eternalId);

    json SerializeAll() const;
    void DeserializeAll(const json& j);

private:
    EternalConvergenceEngine() = default;
    ~EternalConvergenceEngine() = default;
    EternalConvergenceEngine(const EternalConvergenceEngine&) = delete;
    EternalConvergenceEngine& operator=(const EternalConvergenceEngine&) = delete;

    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<EternalConvergence>> eternalConvergences_;
    std::map<std::string, std::shared_ptr<ConvergenceNode>> nodes_;
    std::map<std::string, std::shared_ptr<EternalStream>> streams_;
    std::map<std::string, std::shared_ptr<ConvergenceWave>> waves_;
    std::map<std::string, std::shared_ptr<UnityMatrix>> matrices_;
    std::map<std::string, std::shared_ptr<EternalTensor>> tensors_;
    std::map<std::string, std::shared_ptr<EternalClarity>> clarities_;

    std::string GenerateId() const;
};

} // namespace EternalConvergence
