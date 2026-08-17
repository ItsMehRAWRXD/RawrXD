#include "ElasticEngine.hpp"
#include "../gguf_tensor_loader.hpp"
#include <iostream>
#include <algorithm>
#include <cmath>

namespace RawrXD::Elastic {

// ============================================================================
// Construction / Destruction
// ============================================================================
ElasticEngine::ElasticEngine(ElasticConfig config)
    : config_(std::move(config)) {}

ElasticEngine::~ElasticEngine() = default;

// ============================================================================
// Initialize
// ============================================================================
bool ElasticEngine::Initialize(std::shared_ptr<ElasticGGUFIndex> index,
                               RawrXD::TensorExecutionRouter* router,
                               RawrXD::Governance::UnifiedTriggerOrchestrator* orchestrator,
                               RawrXD::Governance::HardwareGovernor* governor,
                               RawrXD::Memory::PredictiveMemoryManager* predictive_mem) {
    if (!index || !router) return false;

    index_ = std::move(index);
    router_ = router;
    orchestrator_ = orchestrator;
    governor_ = governor;
    predictive_mem_ = predictive_mem;

    // Build compute-block index from GGUF
    if (!index_->BuildIndexFromTensors()) {
        std::cerr << "[ElasticEngine] Failed to build index from tensors.\n";
        return false;
    }

    // Create residency manager
    residency_mgr_ = std::make_unique<ElasticResidencyManager>(*index_);

    // Detect architecture
    profile_.type = index_->DetectArchitecture();
    profile_.blocks = index_->GetAllBlocks();
    profile_.total_layers = 0;
    profile_.num_experts = 0;
    profile_.total_tensor_bytes = 0;

    for (const auto& block : profile_.blocks) {
        profile_.total_tensor_bytes += block.byte_size;
        if (block.layer_idx > profile_.total_layers) {
            profile_.total_layers = block.layer_idx;
        }
        if (block.is_expert && block.expert_idx >= profile_.num_experts) {
            profile_.num_experts = block.expert_idx + 1;
        }
    }
    if (profile_.total_layers > 0) ++profile_.total_layers; // layers are 0-indexed

    profile_.supports_dss = (profile_.type == ModelArchitectureType::Dense);
    profile_.active_experts_per_token = config_.moe_top_k;

    // Initialize metrics
    UpdatePhysicalBpw();
    metrics_.physical_bytes = profile_.total_tensor_bytes;

    std::cout << "[ElasticEngine] Initialized. Architecture: "
              << static_cast<int>(profile_.type)
              << " | Blocks: " << profile_.blocks.size()
              << " | Layers: " << profile_.total_layers
              << " | Bytes: " << (profile_.total_tensor_bytes / (1024 * 1024)) << " MB\n";
    return true;
}

// ============================================================================
// Architecture detection (delegates to index)
// ============================================================================
ModelArchitectureType ElasticEngine::DetectArchitecture() const {
    if (!index_) return ModelArchitectureType::Unknown;
    return index_->DetectArchitecture();
}

// ============================================================================
// Residency management
// ============================================================================
bool ElasticEngine::EnsureBlockResident(uint32_t block_id) {
    if (!residency_mgr_) return false;

    // Try GPU residency first
    void* gpu_buf = residency_mgr_->RequireGpuResident(block_id);
    if (gpu_buf) return true;

    // Fall back to CPU mmap
    const void* cpu_ptr = residency_mgr_->RequireCpuResident(block_id);
    return cpu_ptr != nullptr;
}

void ElasticEngine::EnforceVramBudget() {
    if (!residency_mgr_) return;
    // Eviction is handled automatically by RequireGpuResident
    // This method is a no-op placeholder for explicit budget enforcement
}

// ============================================================================
// Dense layer forward pass with DSS
// ============================================================================
void ElasticEngine::ForwardLayerDense(uint32_t layer_idx,
                                       const float* input_activations,
                                       size_t hidden_dim,
                                       float* output_buffer) {
    if (!router_ || !residency_mgr_) return;

    // Gather blocks for this layer
    std::vector<const ComputeBlock*> layer_blocks;
    for (const auto& block : profile_.blocks) {
        if (block.layer_idx == layer_idx) {
            layer_blocks.push_back(&block);
        }
    }

    if (layer_blocks.empty()) return;

    // For dense models, each "block" is a column-slice of the weight matrix.
    // We check activation magnitude for the corresponding input chunk.
    size_t blocks_per_layer = layer_blocks.size();
    size_t slice_dim = hidden_dim / blocks_per_layer;
    if (slice_dim == 0) slice_dim = hidden_dim;

    for (size_t i = 0; i < layer_blocks.size(); ++i) {
        const auto* block = layer_blocks[i];
        uint64_t dss_key = MakeDssKey(layer_idx, block->block_id);

        // Compute L1 norm of activation chunk feeding this block
        float l1_norm = 0.0f;
        size_t start_idx = i * slice_dim;
        size_t end_idx = std::min(start_idx + slice_dim, hidden_dim);
        for (size_t j = start_idx; j < end_idx; ++j) {
            l1_norm += std::abs(input_activations[j]);
        }

        // DSS: if activation is dead, skip this block
        bool skip = false;
        if (config_.enable_dss && l1_norm < config_.dss_activation_threshold) {
            auto it = dss_profiles_.find(dss_key);
            if (it != dss_profiles_.end() && it->second.dss_state == DssBlockState::Specialized) {
                skip = true;
                ++metrics_.dss_skipped_blocks;
            }
        }

        if (skip) continue;

        // Ensure residency and execute
        void* gpu_buf = residency_mgr_->RequireGpuResident(block->block_id);
        if (gpu_buf) {
            // Construct TensorHandle for router dispatch
            RawrXD::TensorHandle weight{};
            weight.name = block->name.c_str();
            weight.host_ptr = nullptr; // GPU resident
            weight.device_ptr = gpu_buf;
            weight.bytes = block->byte_size;
            weight.is_hot = true;
            weight.is_quantized = (block->ggml_type > 1);
            weight.quant_kind = block->ggml_type;

            RawrXD::TensorView input_view{};
            input_view.data = const_cast<float*>(input_activations + start_idx);
            input_view.size = end_idx - start_idx;

            RawrXD::TensorView output_view{};
            output_view.data = output_buffer + start_idx;
            output_view.size = end_idx - start_idx;

            router_->matmul(input_view, weight, output_view,
                            static_cast<int>(end_idx - start_idx),
                            static_cast<int>(slice_dim));
        }

        ++metrics_.dss_executed_blocks;
    }

    UpdateActiveComputeRatio();
}

// ============================================================================
// Native MoE layer forward pass
// ============================================================================
void ElasticEngine::ForwardLayerMoE(uint32_t layer_idx,
                                     const float* input_activations,
                                     size_t hidden_dim,
                                     float* output_buffer) {
    if (!router_ || !residency_mgr_) return;

    // Gather expert blocks for this layer
    std::vector<const ComputeBlock*> experts;
    for (const auto& block : profile_.blocks) {
        if (block.layer_idx == layer_idx && block.is_expert) {
            experts.push_back(&block);
        }
    }

    if (experts.empty()) return;

    // Naive top-K: select first K experts (placeholder for real gating network)
    // In production, this uses the model's native gate weights.
    uint32_t k = std::min(config_.moe_top_k, static_cast<uint32_t>(experts.size()));

    for (uint32_t i = 0; i < k; ++i) {
        const auto* expert = experts[i];
        void* gpu_buf = residency_mgr_->RequireGpuResident(expert->block_id);
        if (!gpu_buf) continue;

        RawrXD::TensorHandle weight{};
        weight.name = expert->name.c_str();
        weight.host_ptr = nullptr;
        weight.device_ptr = gpu_buf;
        weight.bytes = expert->byte_size;
        weight.is_hot = true;
        weight.is_quantized = (expert->ggml_type > 1);
        weight.quant_kind = expert->ggml_type;

        RawrXD::TensorView input_view{};
        input_view.data = const_cast<float*>(input_activations);
        input_view.size = hidden_dim;

        RawrXD::TensorView output_view{};
        output_view.data = output_buffer;
        output_view.size = hidden_dim;

        router_->matmul(input_view, weight, output_view,
                        static_cast<int>(hidden_dim),
                        static_cast<int>(hidden_dim));
    }

    metrics_.native_moe_active_experts = k;
    metrics_.native_moe_total_experts = static_cast<uint64_t>(experts.size());
}

// ============================================================================
// Single-tensor matmul via elastic residency (transformer integration)
// ============================================================================
bool ElasticEngine::ExecuteMatMul(const std::string& tensor_name,
                                   const float* input, float* output,
                                   std::size_t input_dim, std::size_t output_dim,
                                   uint32_t layer_idx) {
    if (!router_ || !residency_mgr_ || !index_) return false;

    // Find the compute block for this tensor
    const auto* block = index_->FindBlockByName(tensor_name);
    if (!block) {
        // Tensor not indexed by elastic — fall through to let caller handle
        return false;
    }

    // Ensure block is resident (GPU preferred, CPU mmap fallback)
    void* gpu_buf = residency_mgr_->RequireGpuResident(block->block_id);
    const void* cpu_ptr = nullptr;
    if (!gpu_buf) {
        cpu_ptr = residency_mgr_->RequireCpuResident(block->block_id);
        if (!cpu_ptr) {
            printf("[ElasticEngine] ExecuteMatMul FAILED: cannot resident block %u (%s)\n",
                   block->block_id, tensor_name.c_str());
            return false;
        }
    }

    // Build TensorHandle for router dispatch
    RawrXD::TensorHandle weight{};
    weight.name = block->name.c_str();
    weight.host_ptr = const_cast<void*>(cpu_ptr);
    weight.device_ptr = gpu_buf;
    weight.bytes = block->byte_size;
    weight.is_hot = (gpu_buf != nullptr);
    weight.is_quantized = (block->ggml_type > 1);
    weight.quant_kind = block->ggml_type;

    RawrXD::TensorView input_view{};
    input_view.data = const_cast<float*>(input);
    input_view.size = input_dim;

    RawrXD::TensorView output_view{};
    output_view.data = output;
    output_view.size = output_dim;

    // Advance router layer and dispatch
    router_->advanceLayer(layer_idx);
    bool ok = router_->dispatchMatmul(
        input_view, weight, output_view,
        static_cast<int>(output_dim), static_cast<int>(input_dim),
        RawrXD::TensorExecutionRouter::MatmulBackendDispatch{});

    if (ok) {
        ++metrics_.dss_executed_blocks;
        // Record telemetry for predictive memory
        if (predictive_mem_) {
            // TODO: map block_id to TensorId and call predictive_mem_->recordCompletion
        }
    }

    return ok;
}

// ============================================================================
// DSS profiling
// ============================================================================
void ElasticEngine::RecordDssObservation(uint32_t block_id, float activation_magnitude) {
    if (!config_.enable_dss) return;

    std::unique_lock<std::shared_mutex> lock(mutex_);

    // Find the block's layer
    uint32_t layer = 0;
    for (const auto& block : profile_.blocks) {
        if (block.block_id == block_id) {
            layer = block.layer_idx;
            break;
        }
    }

    uint64_t key = MakeDssKey(layer, block_id);
    auto& profile = dss_profiles_[key];
    profile.block_id = block_id;
    profile.layer_idx = layer;
    ++profile.total_invocations;

    // Update running average of activation magnitude
    double alpha = 1.0 / std::min(profile.total_invocations, config_.dss_max_observations);
    profile.avg_activation_magnitude =
        (1.0 - alpha) * profile.avg_activation_magnitude + alpha * activation_magnitude;
    profile.max_activation_magnitude = std::max(profile.max_activation_magnitude,
                                                 static_cast<double>(activation_magnitude));
    if (profile.min_activation_magnitude == 0.0) {
        profile.min_activation_magnitude = activation_magnitude;
    } else {
        profile.min_activation_magnitude = std::min(profile.min_activation_magnitude,
                                                     static_cast<double>(activation_magnitude));
    }
}

void ElasticEngine::EvaluateDssCandidates() {
    if (!config_.enable_dss) return;

    std::unique_lock<std::shared_mutex> lock(mutex_);

    for (auto& [key, profile] : dss_profiles_) {
        if (profile.total_invocations < config_.dss_min_observations) continue;

        switch (profile.dss_state) {
            case DssBlockState::ObserveOnly:
                // Promote to Candidate if activation is consistently low
                if (profile.avg_activation_magnitude < config_.dss_activation_threshold &&
                    profile.total_invocations >= config_.dss_min_observations) {
                    profile.dss_state = DssBlockState::Candidate;
                }
                break;

            case DssBlockState::Candidate:
                // Promote to Validated if error remains acceptable
                if (profile.max_contribution_error < config_.dss_max_acceptable_error) {
                    profile.dss_state = DssBlockState::Validated;
                } else {
                    // Demote back to ObserveOnly if error too high
                    profile.dss_state = DssBlockState::ObserveOnly;
                }
                break;

            case DssBlockState::Validated:
                // Promote to Specialized after sufficient validation
                if (profile.total_invocations >= config_.dss_min_observations * 2) {
                    profile.dss_state = DssBlockState::Specialized;
                }
                break;

            case DssBlockState::Specialized:
                // Demote if error exceeds threshold
                if (profile.max_contribution_error > config_.dss_max_acceptable_error) {
                    profile.dss_state = DssBlockState::ForcedActive;
                }
                break;

            case DssBlockState::ForcedActive:
                // Stay here; manual reset required
                break;
        }
    }
}

// ============================================================================
// Metrics
// ============================================================================
ElasticMetrics ElasticEngine::GetMetrics() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    ElasticMetrics copy = metrics_;
    if (residency_mgr_) {
        copy.resident_vram_bytes = residency_mgr_->GpuResidentBytes();
    }
    return copy;
}

void ElasticEngine::ResetMetrics() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    metrics_ = ElasticMetrics{};
    UpdatePhysicalBpw();
    metrics_.physical_bytes = profile_.total_tensor_bytes;
}

// ============================================================================
// Predictive memory integration
// ============================================================================
void ElasticEngine::PrefetchLayer(uint32_t layer_idx) {
    if (!predictive_mem_ || !config_.enable_prefetch) return;

    // PredictiveMemoryManager handles prefetch; Elastic just informs it
    // which blocks are likely needed
    for (const auto& block : profile_.blocks) {
        if (block.layer_idx >= layer_idx &&
            block.layer_idx <= layer_idx + config_.prefetch_lookahead) {
            // Inform predictive memory of upcoming need
            // The actual prefetch is managed by PredictiveMemoryManager
        }
    }
}

void ElasticEngine::RecordCompletion(uint32_t block_id) {
    if (!predictive_mem_) return;
    // PredictiveMemoryManager records completion for working-set prediction
}

// ============================================================================
// Internal: update physical bpw from actual GGUF data
// ============================================================================
void ElasticEngine::UpdatePhysicalBpw() {
    if (profile_.total_tensor_bytes == 0 || profile_.blocks.empty()) {
        metrics_.physical_bpw = 0.0;
        return;
    }

    uint64_t total_weights = 0;
    for (const auto& block : profile_.blocks) {
        total_weights += block.num_weights;
    }

    if (total_weights == 0) {
        metrics_.physical_bpw = 0.0;
        return;
    }

    // physical_bpw = (total bytes * 8 bits/byte) / total weights
    metrics_.physical_bpw = static_cast<double>(profile_.total_tensor_bytes * 8) /
                            static_cast<double>(total_weights);
}

// ============================================================================
// Internal: update active compute ratio from DSS state
// ============================================================================
void ElasticEngine::UpdateActiveComputeRatio() {
    uint64_t total_blocks = profile_.blocks.size();
    if (total_blocks == 0) {
        metrics_.active_compute_ratio = 1.0;
        return;
    }

    uint64_t active_blocks = 0;
    for (const auto& block : profile_.blocks) {
        uint64_t key = MakeDssKey(block.layer_idx, block.block_id);
        auto it = dss_profiles_.find(key);
        if (it == dss_profiles_.end() || it->second.dss_state != DssBlockState::Specialized) {
            ++active_blocks;
        }
    }

    metrics_.active_compute_ratio = static_cast<double>(active_blocks) /
                                    static_cast<double>(total_blocks);
    metrics_.effective_bpw = metrics_.physical_bpw * metrics_.active_compute_ratio;
}

} // namespace RawrXD::Elastic
