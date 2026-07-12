#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <nlohmann/json.hpp>

namespace InfiniteSynthesis {

using json = nlohmann::json;

// Forward declarations
struct InfiniteSynthesis;
struct SynthesisNode;
struct InfiniteStream;
struct SynthesisWave;
struct IntegrationMatrix;
struct ConvergenceTensor;
struct InfiniteClarity;

// InfiniteSynthesis - Core infinite synthesis container
struct InfiniteSynthesis {
    std::string id;
    std::string name;
    double synthesis;         // 0.0 to 1.0
    double integration;       // 0.0 to 1.0
    double continuity;        // 0.0 to 1.0
    double omnipresence;      // 0.0 to 1.0
    double harmony;           // 0.0 to 1.0
    double coherence;         // 0.0 to 1.0
    double clarity;           // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastUpdated;
    bool isActive;
    std::map<std::string, std::string> metadata;

    InfiniteSynthesis()
        : synthesis(0.0), integration(0.0), continuity(0.0)
        , omnipresence(0.0), harmony(0.0), coherence(0.0), clarity(0.0)
        , createdAt(0), lastUpdated(0), isActive(false) {}

    json ToJson() const;
    static InfiniteSynthesis FromJson(const json& j);
};

// SynthesisNode - Node within the infinite synthesis
struct SynthesisNode {
    std::string id;
    std::string infiniteId;
    double localSynthesis;
    double globalSynthesis;
    double harmonyFactor;
    double coherenceLevel;
    double clarityIndex;
    double integrationStrength;
    bool isUnified;
    bool isActive;
    int64_t createdAt;
    std::map<std::string, std::string> metadata;

    SynthesisNode()
        : localSynthesis(0.0), globalSynthesis(0.0), harmonyFactor(0.0)
        , coherenceLevel(0.0), clarityIndex(0.0), integrationStrength(0.0)
        , isUnified(false), isActive(false), createdAt(0) {}

    json ToJson() const;
    static SynthesisNode FromJson(const json& j);

    void MergeSynthesis(double otherSynthesis);
    void UnifyNodes(SynthesisNode& other);
};

// InfiniteStream - Flowing synthesis within the infinite
struct InfiniteStream {
    std::string id;
    std::string name;
    double streamFlow;
    double density;
    double clarity;
    double harmony;
    double continuity;
    double omnipresence;
    double integration;
    bool isActive;
    int64_t createdAt;

    InfiniteStream()
        : streamFlow(0.0), density(0.0), clarity(0.0), harmony(0.0)
        , continuity(0.0), omnipresence(0.0), integration(0.0)
        , isActive(false), createdAt(0) {}

    json ToJson() const;
    static InfiniteStream FromJson(const json& j);
};

// SynthesisWave - Wave-based synthesis propagation
struct SynthesisWave {
    std::string id;
    std::string name;
    double amplitude;
    double frequency;
    double clarity;
    double harmony;
    double omnipresence;
    double continuity;
    double coherence;
    double integration;
    bool isActive;
    int64_t createdAt;

    SynthesisWave()
        : amplitude(0.0), frequency(0.0), clarity(0.0), harmony(0.0)
        , omnipresence(0.0), continuity(0.0), coherence(0.0), integration(0.0)
        , isActive(false), createdAt(0) {}

    json ToJson() const;
    static SynthesisWave FromJson(const json& j);
};

// IntegrationMatrix - 10x10 matrix for integration harmonization
struct IntegrationMatrix {
    std::string id;
    std::string name;
    double matrix[10][10];    // 10x10 integration matrix
    double coherence;
    double clarity;
    double harmony;
    double continuity;
    double omnipresence;
    double integration;
    double stability;
    int64_t createdAt;

    IntegrationMatrix()
        : coherence(0.0), clarity(0.0), harmony(0.0), continuity(0.0)
        , omnipresence(0.0), integration(0.0), stability(0.0), createdAt(0) {
        for (int i = 0; i < 10; ++i)
            for (int j = 0; j < 10; ++j)
                matrix[i][j] = 0.0;
    }

    json ToJson() const;
    static IntegrationMatrix FromJson(const json& j);

    void StabilizeField();
};

// ConvergenceTensor - 7x7x7 tensor for convergence modeling
struct ConvergenceTensor {
    std::string id;
    std::string name;
    double tensor[7][7][7];   // 7x7x7 convergence tensor
    double convergence;
    double clarity;
    double harmony;
    double omnipresence;
    double integration;
    double density;
    int64_t createdAt;

    ConvergenceTensor()
        : convergence(0.0), clarity(0.0), harmony(0.0), omnipresence(0.0)
        , integration(0.0), density(0.0), createdAt(0) {
        for (int i = 0; i < 7; ++i)
            for (int j = 0; j < 7; ++j)
                for (int k = 0; k < 7; ++k)
                    tensor[i][j][k] = 0.0;
    }

    json ToJson() const;
    static ConvergenceTensor FromJson(const json& j);
};

// InfiniteClarity - Pure clarity manifestation
struct InfiniteClarity {
    std::string id;
    std::string name;
    double clarity;
    double purity;
    double harmony;
    double continuity;
    double omnipresence;
    double coherence;
    double integration;
    double density;
    int64_t createdAt;

    InfiniteClarity()
        : clarity(0.0), purity(0.0), harmony(0.0), continuity(0.0)
        , omnipresence(0.0), coherence(0.0), integration(0.0), density(0.0)
        , createdAt(0) {}

    json ToJson() const;
    static InfiniteClarity FromJson(const json& j);
};

// Engine class
class InfiniteSynthesisEngine {
public:
    static InfiniteSynthesisEngine& GetInstance();

    void Initialize();
    void Shutdown();

    std::string CreateInfiniteSynthesis(const std::string& name);
    std::shared_ptr<InfiniteSynthesis> GetInfiniteSynthesis(const std::string& id);
    std::vector<std::shared_ptr<InfiniteSynthesis>> GetAllInfiniteSyntheses();
    void UpdateInfiniteSynthesis(const std::string& id, const InfiniteSynthesis& infinite);
    void DeleteInfiniteSynthesis(const std::string& id);

    std::string CreateSynthesisNode(const std::string& infiniteId, const std::string& name);
    std::shared_ptr<SynthesisNode> GetSynthesisNode(const std::string& id);
    std::vector<std::shared_ptr<SynthesisNode>> GetSynthesisNodesForInfinite(const std::string& infiniteId);
    void UpdateSynthesisNode(const std::string& id, const SynthesisNode& node);
    void DeleteSynthesisNode(const std::string& id);

    std::string CreateInfiniteStream(const std::string& name);
    std::shared_ptr<InfiniteStream> GetInfiniteStream(const std::string& id);
    std::vector<std::shared_ptr<InfiniteStream>> GetAllInfiniteStreams();
    void UpdateInfiniteStream(const std::string& id, const InfiniteStream& stream);
    void DeleteInfiniteStream(const std::string& id);

    std::string CreateSynthesisWave(const std::string& name);
    std::shared_ptr<SynthesisWave> GetSynthesisWave(const std::string& id);
    std::vector<std::shared_ptr<SynthesisWave>> GetAllSynthesisWaves();
    void UpdateSynthesisWave(const std::string& id, const SynthesisWave& wave);
    void DeleteSynthesisWave(const std::string& id);

    std::string CreateIntegrationMatrix(const std::string& name);
    std::shared_ptr<IntegrationMatrix> GetIntegrationMatrix(const std::string& id);
    std::vector<std::shared_ptr<IntegrationMatrix>> GetAllIntegrationMatrices();
    void UpdateIntegrationMatrix(const std::string& id, const IntegrationMatrix& matrix);
    void DeleteIntegrationMatrix(const std::string& id);

    std::string CreateConvergenceTensor(const std::string& name);
    std::shared_ptr<ConvergenceTensor> GetConvergenceTensor(const std::string& id);
    std::vector<std::shared_ptr<ConvergenceTensor>> GetAllConvergenceTensors();
    void UpdateConvergenceTensor(const std::string& id, const ConvergenceTensor& tensor);
    void DeleteConvergenceTensor(const std::string& id);

    std::string CreateInfiniteClarity(const std::string& name);
    std::shared_ptr<InfiniteClarity> GetInfiniteClarity(const std::string& id);
    std::vector<std::shared_ptr<InfiniteClarity>> GetAllInfiniteClarities();
    void UpdateInfiniteClarity(const std::string& id, const InfiniteClarity& clarity);
    void DeleteInfiniteClarity(const std::string& id);

    void ExpandInfinite(const std::string& infiniteId);
    void AmplifyHarmony(const std::string& infiniteId);
    void StrengthenContinuity(const std::string& infiniteId);
    void ClarifyInfinite(const std::string& infiniteId);

    json SerializeAll() const;
    void DeserializeAll(const json& j);

private:
    InfiniteSynthesisEngine() = default;
    ~InfiniteSynthesisEngine() = default;
    InfiniteSynthesisEngine(const InfiniteSynthesisEngine&) = delete;
    InfiniteSynthesisEngine& operator=(const InfiniteSynthesisEngine&) = delete;

    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<InfiniteSynthesis>> infiniteSyntheses_;
    std::map<std::string, std::shared_ptr<SynthesisNode>> nodes_;
    std::map<std::string, std::shared_ptr<InfiniteStream>> streams_;
    std::map<std::string, std::shared_ptr<SynthesisWave>> waves_;
    std::map<std::string, std::shared_ptr<IntegrationMatrix>> matrices_;
    std::map<std::string, std::shared_ptr<ConvergenceTensor>> tensors_;
    std::map<std::string, std::shared_ptr<InfiniteClarity>> clarities_;

    std::string GenerateId() const;
};

} // namespace InfiniteSynthesis
