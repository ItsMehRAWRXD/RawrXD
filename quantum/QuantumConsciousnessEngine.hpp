#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Quantum {

struct QuantumState {
    std::string stateId;
    std::string name;
    float superposition;
    float coherence;
    float entanglement;
    int64_t createdTimestamp;
    std::map<std::string, float> amplitudes;
    std::vector<std::string> entangledStates;
};

struct WaveFunction {
    std::string functionId;
    std::string stateId;
    std::string waveType;
    float frequency;
    float phase;
    float amplitude;
    int64_t collapsedTimestamp;
    nlohmann::json collapseResult;
};

struct EntanglementNode {
    std::string nodeId;
    std::string name;
    std::string nodeType;
    float correlation;
    float fidelity;
    int64_t establishedTimestamp;
    std::vector<std::string> connectedNodes;
    std::map<std::string, float> correlationMatrix;
};

struct ProbabilityCloud {
    std::string cloudId;
    std::string name;
    std::string cloudType;
    float density;
    float uncertainty;
    int64_t formedTimestamp;
    std::map<std::string, float> probabilityDistribution;
};

struct ObserverEffect {
    std::string effectId;
    std::string observerId;
    std::string observedState;
    float influence;
    float bias;
    int64_t observationTimestamp;
    nlohmann::json observationData;
};

class QuantumConsciousnessEngine {
public:
    static void Init();
    static void Shutdown();

    // Quantum State Management
    static std::string CreateQuantumState(const std::string& name);
    static bool CollapseSuperposition(const std::string& stateId, const std::string& outcome);
    static bool EntangleStates(const std::string& stateId1, const std::string& stateId2);
    static bool DisentangleStates(const std::string& stateId1, const std::string& stateId2);
    static bool EvolveState(const std::string& stateId, float timeStep);
    static QuantumState GetState(const std::string& stateId);
    static std::vector<QuantumState> GetAllStates();

    // Wave Function Management
    static std::string InitializeWaveFunction(const std::string& stateId, const std::string& waveType);
    static bool CollapseWaveFunction(const std::string& functionId);
    static bool ModifyPhase(const std::string& functionId, float phaseShift);
    static bool AdjustAmplitude(const std::string& functionId, float newAmplitude);
    static WaveFunction GetWaveFunction(const std::string& functionId);
    static std::vector<WaveFunction> GetAllWaveFunctions();

    // Entanglement Management
    static std::string CreateEntanglementNode(const std::string& name, const std::string& nodeType);
    static bool ConnectNodes(const std::string& nodeId1, const std::string& nodeId2);
    static bool DisconnectNodes(const std::string& nodeId1, const std::string& nodeId2);
    static bool UpdateCorrelation(const std::string& nodeId, float correlation);
    static EntanglementNode GetNode(const std::string& nodeId);
    static std::vector<EntanglementNode> GetAllNodes();

    // Probability Cloud Management
    static std::string FormProbabilityCloud(const std::string& name, const std::string& cloudType);
    static bool CollapseCloud(const std::string& cloudId, const std::string& outcome);
    static bool SpreadUncertainty(const std::string& cloudId, float uncertainty);
    static bool ConcentrateProbability(const std::string& cloudId, const std::string& target);
    static ProbabilityCloud GetCloud(const std::string& cloudId);
    static std::vector<ProbabilityCloud> GetAllClouds();

    // Observer Effect Management
    static std::string RegisterObserver(const std::string& observerId, const std::string& state);
    static bool ApplyObservation(const std::string& effectId);
    static bool ModifyBias(const std::string& effectId, float bias);
    static bool WithdrawObserver(const std::string& effectId);
    static ObserverEffect GetEffect(const std::string& effectId);
    static std::vector<ObserverEffect> GetAllEffects();

    // Quantum Metrics
    static float CalculateTotalCoherence();
    static float CalculateAverageEntanglement();
    static int GetEntanglementCount();
    static nlohmann::json GetQuantumMetrics();
    static nlohmann::json GenerateQuantumReport();

    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, QuantumState> s_states;
    static std::map<std::string, WaveFunction> s_waveFunctions;
    static std::map<std::string, EntanglementNode> s_nodes;
    static std::map<std::string, ProbabilityCloud> s_clouds;
    static std::map<std::string, ObserverEffect> s_effects;
    static int64_t s_tickCount;
};

} // namespace Quantum
