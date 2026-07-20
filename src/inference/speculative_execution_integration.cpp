//============================================================================
// speculative_execution_integration.cpp
//
// VAL-032: Integration Layer Implementation
//============================================================================

#include "speculative_execution_integration.hpp"
#include <cstring>
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Inference {

//============================================================================
// SpeculativeExecutionPipeline Implementation
//============================================================================

SpeculativeExecutionPipeline::SpeculativeExecutionPipeline(
    std::unique_ptr<IDraftModel> draft_model,
    std::unique_ptr<ITargetModel> target_model,
    const SpeculativeConfig& config
) : config_(config),
    draft_model_(std::move(draft_model)),
    target_model_(std::move(target_model)) {
}

SpeculativeExecutionPipeline::~SpeculativeExecutionPipeline() = default;

bool SpeculativeExecutionPipeline::Initialize() {
    if (!draft_model_ || !target_model_) {
        return false;
    }
    
    if (!draft_model_->IsReady() || !target_model_->IsReady()) {
        return false;
    }
    
    // Initialize execution engine with kernel
    Kernels::TreeAttentionConfig kernel_config;
    kernel_config.max_candidates = config_.max_batch_size;
    kernel_config.acceptance_threshold = config_.acceptance_threshold;
    kernel_config.enable_telemetry = config_.enable_kernel_telemetry;
    kernel_config.enable_residency_hooks = config_.enable_residency_hooks;
    
    execution_engine_ = std::make_unique<Kernels::SpeculativeExecutionEngine>(
        kernel_config
    );
    
    // Wire residency planner if available
    if (residency_planner_) {
        execution_engine_->SetResidencyPlanner(residency_planner_);
        
        // Prefetch draft model weights
        auto weight_ids = draft_model_->GetWeightIds();
        execution_engine_->PrefetchDraftTensors(weight_ids);
    }
    
    initialized_ = true;
    return true;
}

SpeculativeResult SpeculativeExecutionPipeline::Generate(
    const std::vector<uint32_t>& prompt,
    uint32_t max_new_tokens
) {
    SpeculativeResult result;
    current_context_ = prompt;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    uint32_t generated = 0;
    while (generated < max_new_tokens) {
        // Step with speculation
        uint32_t token = Step(generated > 0 ? current_context_.back() : 0);
        
        if (token == 0) {
            // Error or end of generation
            break;
        }
        
        result.accepted_tokens.push_back(token);
        current_context_.push_back(token);
        generated++;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time
    );
    
    result.used_speculation = config_.enable_tree_attention;
    
    // Get telemetry from execution engine
    if (execution_engine_) {
        const auto& telemetry = execution_engine_->GetTelemetry();
        result.acceptance_rate = telemetry.GetAcceptanceRate();
    }
    
    return result;
}

uint32_t SpeculativeExecutionPipeline::Step(uint32_t last_token) {
    if (!initialized_ || !execution_engine_) {
        // Fallback: direct target model generation
        if (target_model_) {
            return target_model_->Generate(current_context_);
        }
        return 0;
    }
    
    // 1. Generate draft tokens
    auto draft_start = std::chrono::high_resolution_clock::now();
    auto draft_tokens = GenerateDraftTokens(config_.draft_tokens);
    auto draft_end = std::chrono::high_resolution_clock::now();
    
    if (draft_tokens.empty()) {
        // Draft model failed, fallback to target
        return target_model_->Generate(current_context_);
    }
    
    // 2. Verify draft tokens
    auto verify_start = std::chrono::high_resolution_clock::now();
    auto verification = VerifyDraftTokens(draft_tokens);
    auto verify_end = std::chrono::high_resolution_clock::now();
    
    // 3. Process results
    if (verification.accepted_count == draft_tokens.size()) {
        // All accepted: return first draft token
        // In full implementation: could generate bonus token
        CommitAcceptedTokens({draft_tokens[0]});
        return draft_tokens[0];
    }
    
    if (verification.accepted_count > 0) {
        // Partial acceptance: commit accepted, rollback rejected
        std::vector<uint32_t> accepted(
            draft_tokens.begin(),
            draft_tokens.begin() + verification.accepted_count
        );
        CommitAcceptedTokens(accepted);
        
        // Rollback rejected
        RollbackRejectedTokens(verification.rejection_mask);
        
        return draft_tokens[verification.accepted_count - 1];
    }
    
    // All rejected: rollback and generate from target
    RollbackRejectedTokens(verification.rejection_mask);
    return target_model_->Generate(current_context_);
}

void SpeculativeExecutionPipeline::SetResidencyPlanner(
    Memory::TensorResidencyPlanner* planner
) {
    residency_planner_ = planner;
    if (execution_engine_) {
        execution_engine_->SetResidencyPlanner(planner);
    }
}

Memory::TensorResidencyPlanner* SpeculativeExecutionPipeline::GetResidencyPlanner() const {
    return residency_planner_;
}

const Kernels::SpeculativeTelemetry& SpeculativeExecutionPipeline::GetTelemetry() const {
    if (execution_engine_) {
        return execution_engine_->GetTelemetry();
    }
    
    static Kernels::SpeculativeTelemetry empty;
    return empty;
}

void SpeculativeExecutionPipeline::ResetTelemetry() {
    if (execution_engine_) {
        execution_engine_->ResetTelemetry();
    }
}

const Kernels::TreeAttentionKernel& SpeculativeExecutionPipeline::GetKernel() const {
    if (execution_engine_) {
        return execution_engine_->GetKernel();
    }
    
    static Kernels::TreeAttentionKernel null_kernel{nullptr, nullptr, nullptr, "Null", 0};
    return null_kernel;
}

bool SpeculativeExecutionPipeline::IsReady() const {
    return initialized_ && 
           draft_model_ && draft_model_->IsReady() &&
           target_model_ && target_model_->IsReady() &&
           execution_engine_ != nullptr;
}

const char* SpeculativeExecutionPipeline::GetKernelName() const {
    return GetKernel().name;
}

std::vector<uint32_t> SpeculativeExecutionPipeline::GenerateDraftTokens(uint32_t count) {
    std::vector<uint32_t> tokens;
    if (!draft_model_) return tokens;
    
    tokens = draft_model_->PredictBatch(current_context_, count);
    return tokens;
}

Kernels::VerificationResult SpeculativeExecutionPipeline::VerifyDraftTokens(
    const std::vector<uint32_t>& draft_tokens
) {
    // Prepare buffers for kernel
    alignas(64) float query[64];
    alignas(64) float keys[16 * 64];
    alignas(64) float tree_mask[64];
    alignas(64) float output_probs[16];
    
    // Initialize with dummy data (in real implementation: embed tokens)
    memset(query, 0, sizeof(query));
    memset(keys, 0, sizeof(keys));
    memset(tree_mask, 0, sizeof(tree_mask));
    
    // Set validity mask
    uint32_t validity = (1u << draft_tokens.size()) - 1;
    *(uint16_t*)tree_mask = static_cast<uint16_t>(validity);
    
    // Set draft probabilities
    for (size_t i = 0; i < draft_tokens.size() && i < 16; i++) {
        tree_mask[16 + i] = draft_model_->GetProbability(draft_tokens[i]);
    }
    
    // Call kernel
    return execution_engine_->VerifyCandidates(query, keys, tree_mask, output_probs);
}

void SpeculativeExecutionPipeline::RollbackRejectedTokens(uint32_t rejection_mask) {
    // In full implementation: invalidate KV cache entries
    // For now: just update context
    (void)rejection_mask;
}

void SpeculativeExecutionPipeline::CommitAcceptedTokens(
    const std::vector<uint32_t>& tokens
) {
    // Tokens already added to context in Step()
    (void)tokens;
}

//============================================================================
// Telemetry Export
//============================================================================

std::string ExportTelemetryToJSON(const Kernels::SpeculativeTelemetry& telemetry) {
    char buffer[1024];
    snprintf(buffer, sizeof(buffer),
        "{\n"
        "  \"candidates_verified\": %llu,\n"
        "  \"tokens_accepted\": %llu,\n"
        "  \"tokens_rejected\": %llu,\n"
        "  \"acceptance_rate\": %.4f,\n"
        "  \"verify_cycles\": %llu,\n"
        "  \"kv_invalidation_cycles\": %llu,\n"
        "  \"residency_events\": %llu\n"
        "}\n",
        telemetry.candidates_verified,
        telemetry.tokens_accepted,
        telemetry.tokens_rejected,
        telemetry.GetAcceptanceRate(),
        telemetry.verify_cycles,
        telemetry.kv_invalidation_cycles,
        telemetry.residency_events
    );
    return std::string(buffer);
}

void PrintTelemetrySummary(
    const Kernels::SpeculativeTelemetry& telemetry,
    FILE* output
) {
    fprintf(output, "\n=== Speculative Execution Telemetry ===\n");
    fprintf(output, "Candidates Verified: %llu\n", telemetry.candidates_verified);
    fprintf(output, "Tokens Accepted:     %llu\n", telemetry.tokens_accepted);
    fprintf(output, "Tokens Rejected:     %llu\n", telemetry.tokens_rejected);
    fprintf(output, "Acceptance Rate:     %.2f%%\n", telemetry.GetAcceptanceRate() * 100);
    fprintf(output, "Verify Cycles:       %llu\n", telemetry.verify_cycles);
    fprintf(output, "KV Invalidation:     %llu cycles\n", telemetry.kv_invalidation_cycles);
    fprintf(output, "Residency Events:    %llu\n", telemetry.residency_events);
    fprintf(output, "=======================================\n\n");
}

} // namespace Inference
} // namespace RawrXD
