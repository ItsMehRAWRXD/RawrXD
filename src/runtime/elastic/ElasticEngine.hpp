#pragma once
#include "ElasticTypes.hpp"
#include "ElasticGGUFIndex.hpp"
#include "ElasticResidencyManager.hpp"
#include "../TensorExecutionRouter.hpp"
#include "../governance/UnifiedTriggerOrchestrator.hpp"
#include "../governance/HardwareGovernor.hpp"
#include "../memory/PredictiveMemoryManager.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <shared_mutex>

namespace RawrXD::Elastic {

// ============================================================================
// ElasticEngine
// ============================================================================
// The top-level policy engine for architecture-adaptive elastic execution.
// Sits between the existing model loader and TensorExecutionRouter.
//
// Responsibilities:
//   - Detect model architecture (Dense / NativeMoE / Hybrid)
//   - Manage compute-block residency via ElasticResidencyManager
//   - Coordinate with PredictiveMemoryManager for prefetch
//   - Execute DSS profiling and specialization (dense models)
//   - Route native MoE top-K expert selection (MoE models)
//   - Report honest ElasticMetrics
//
// Does NOT:
//   - Modify the GGUF file
//   - Convert dense models to MoE
//   - Invent fake quantization formats
// ============================================================================

class ElasticEngine {
public:
    explicit ElasticEngine(ElasticConfig config);
    ~ElasticEngine();

    // Initialize with existing runtime infrastructure
    bool Initialize(std::shared_ptr<ElasticGGUFIndex> index,
                    RawrXD::TensorExecutionRouter* router,
                    RawrXD::Governance::UnifiedTriggerOrchestrator* orchestrator,
                    RawrXD::Governance::HardwareGovernor* governor,
                    RawrXD::Memory::PredictiveMemoryManager* predictive_mem);

    // Architecture detection
    ModelArchitectureType DetectArchitecture() const;
    const ArchitectureProfile& GetProfile() const { return profile_; }

    // Residency management
    bool EnsureBlockResident(uint32_t block_id);
    void EnforceVramBudget();
    ElasticResidencyManager* GetResidencyManager() const { return residency_mgr_.get(); }

    // Execution routing
    void ForwardLayerDense(uint32_t layer_idx,
                           const float* input_activations,
                           size_t hidden_dim,
                           float* output_buffer);
    void ForwardLayerMoE(uint32_t layer_idx,
                         const float* input_activations,
                         size_t hidden_dim,
                         float* output_buffer);

    // Single-tensor matmul via elastic residency (transformer integration point)
    bool ExecuteMatMul(const std::string& tensor_name,
                       const float* input, float* output,
                       std::size_t input_dim, std::size_t output_dim,
                       uint32_t layer_idx);

    // DSS profiling
    void RecordDssObservation(uint32_t block_id, float activation_magnitude);
    void EvaluateDssCandidates();

    // Metrics
    ElasticMetrics GetMetrics() const;
    void ResetMetrics();

    // Predictive memory integration
    void PrefetchLayer(uint32_t layer_idx);
    void RecordCompletion(uint32_t block_id);

private:
    ElasticConfig config_;
    std::shared_ptr<ElasticGGUFIndex> index_;
    std::unique_ptr<ElasticResidencyManager> residency_mgr_;
    RawrXD::TensorExecutionRouter* router_ = nullptr;
    RawrXD::Governance::UnifiedTriggerOrchestrator* orchestrator_ = nullptr;
    RawrXD::Governance::HardwareGovernor* governor_ = nullptr;
    RawrXD::Memory::PredictiveMemoryManager* predictive_mem_ = nullptr;

    ArchitectureProfile profile_;
    mutable std::shared_mutex mutex_;

    // DSS state
    std::unordered_map<uint64_t, DssProfilerRecord> dss_profiles_; // key = (layer << 32) | block_id
    uint64_t global_tick_ = 0;

    // Metrics
    ElasticMetrics metrics_;

    // Internal helpers
    uint64_t MakeDssKey(uint32_t layer, uint32_t block_id) const {
        return (static_cast<uint64_t>(layer) << 32) | block_id;
    }
    void UpdatePhysicalBpw();
    void UpdateActiveComputeRatio();
};

} // namespace RawrXD::Elastic
